use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

pub struct InfraModule;

/// Known debug/sensitive paths to probe.
const DEBUG_PATHS: &[(&str, &str, &str, f64)] = &[
    ("/.env", "ENV file exposed", "CRITICAL", 9.8),
    ("/actuator/env", "Spring Actuator /env endpoint", "CRITICAL", 9.1),
    ("/actuator/mappings", "Spring Actuator /mappings endpoint", "HIGH", 7.5),
    ("/actuator/beans", "Spring Actuator /beans endpoint", "HIGH", 7.5),
    ("/actuator/loggers", "Spring Actuator /loggers endpoint", "HIGH", 7.5),
    ("/.git/HEAD", "Git repository exposed", "CRITICAL", 9.8),
    ("/phpinfo.php", "phpinfo() exposed", "HIGH", 7.8),
    ("/debug", "Debug endpoint accessible", "HIGH", 7.5),
    ("/server-status", "Apache server-status exposed", "MEDIUM", 5.3),
    ("/server-info", "Apache server-info exposed", "MEDIUM", 5.3),
    ("/config.json", "Config file exposed", "CRITICAL", 9.1),
];

#[async_trait]
impl AttackModule for InfraModule {
    fn name(&self) -> &str {
        "infra"
    }

    fn description(&self) -> &str {
        "Tests CORS, HSTS, TLS configuration, debug endpoints, and secrets exposure"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = session.config.target.trim_end_matches('/').to_string();

        // --- Header checks on each endpoint ---
        for endpoint in endpoints {
            let url = &endpoint.full_url;
            if let Ok(resp) = client
                .inner()
                .get(url)
                .header("Origin", "https://evil.nevelio.test")
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                let headers = resp.headers().clone();

                // CORS
                if let Some(f) = check_cors(url, &headers) {
                    findings.push(f);
                }
                // HSTS
                if let Some(f) = check_hsts(url, &headers) {
                    findings.push(f);
                }
                // Security headers
                findings.extend(check_security_headers(url, &headers));
                // Server info disclosure
                if let Some(f) = check_server_disclosure(url, &headers) {
                    findings.push(f);
                }
            }
        }

        // --- Debug endpoints (probe from base URL, deduplicate by path) ---
        let mut probed = std::collections::HashSet::new();
        for &(path, label, severity_str, cvss) in DEBUG_PATHS {
            let url = format!("{}{}", base, path);
            if !probed.insert(url.clone()) {
                continue;
            }
            if let Some(f) = probe_debug_endpoint(client, &url, label, severity_str, cvss).await {
                findings.push(f);
            }
        }

        // --- TLS check (once on base target) ---
        findings.extend(check_tls(client, &base).await);

        // --- Per-endpoint extended checks ---
        for endpoint in endpoints {
            let url = &endpoint.full_url;
            if let Ok(resp) = client
                .inner()
                .get(url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                let headers = resp.headers().clone();
                let body = resp.text().await.unwrap_or_default();

                // CSP
                if let Some(f) = check_csp(url, &headers) {
                    findings.push(f);
                }
                // Referrer-Policy
                if let Some(f) = check_referrer_policy(url, &headers) {
                    findings.push(f);
                }
                // Cookie flags
                findings.extend(check_cookie_flags(url, &headers));
                // Secrets in response body
                findings.extend(check_secrets_in_response(url, &body));
                // Stack traces in response body
                if let Some(f) = check_stack_traces(url, &body) {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

fn check_cors(url: &str, headers: &reqwest::header::HeaderMap) -> Option<Finding> {
    let acao = headers
        .get("access-control-allow-origin")?
        .to_str()
        .ok()?;

    let is_vuln = acao == "*"
        || acao.eq_ignore_ascii_case("https://evil.nevelio.test")
        || acao == "null";

    if !is_vuln {
        return None;
    }

    let detail = if acao == "*" {
        "wildcard (*)"
    } else if acao == "null" {
        "null origin"
    } else {
        "origin reflection"
    };

    let mut f = Finding::new(
        format!("CORS misconfiguration — {}", detail),
        Severity::High,
        7.5,
        "infra",
        url,
        "GET",
    );
    f.description = format!(
        "The endpoint reflects 'Access-Control-Allow-Origin: {}'. \
         Cross-origin requests from any domain can read the response.",
        acao
    );
    f.recommendation =
        "Restrict Access-Control-Allow-Origin to an explicit whitelist of trusted origins. \
         Never use '*' with credentials."
            .to_string();
    f.cwe = Some("CWE-942".to_string());
    f.references = vec![
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing".to_string(),
    ];
    Some(f)
}

fn check_hsts(url: &str, headers: &reqwest::header::HeaderMap) -> Option<Finding> {
    let hsts = headers.get("strict-transport-security");

    match hsts {
        None => {
            let mut f = Finding::new(
                "HSTS header missing",
                Severity::High,
                7.4,
                "infra",
                url,
                "GET",
            );
            f.description =
                "The Strict-Transport-Security header is absent. Clients may connect over HTTP."
                    .to_string();
            f.recommendation =
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
                    .to_string();
            f.cwe = Some("CWE-319".to_string());
            Some(f)
        }
        Some(value) => {
            let val = value.to_str().unwrap_or("");
            if let Some(max_age) = extract_max_age(val) {
                if max_age < 31_536_000 {
                    let mut f = Finding::new(
                        "HSTS max-age too short",
                        Severity::Medium,
                        5.3,
                        "infra",
                        url,
                        "GET",
                    );
                    f.description = format!(
                        "HSTS max-age is {} seconds (< 1 year). \
                         Browsers may not enforce HTTPS for long enough.",
                        max_age
                    );
                    f.recommendation =
                        "Set max-age to at least 31536000 (1 year) and add includeSubDomains."
                            .to_string();
                    return Some(f);
                }
            }
            None
        }
    }
}

fn check_security_headers(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    // X-Content-Type-Options
    match headers.get("x-content-type-options").and_then(|v| v.to_str().ok()) {
        None => {
            let mut f = Finding::new(
                "X-Content-Type-Options missing",
                Severity::Low,
                3.7,
                "infra",
                url,
                "GET",
            );
            f.description = "The X-Content-Type-Options header is absent. \
                             Browsers may MIME-sniff responses."
                .to_string();
            f.recommendation = "Add 'X-Content-Type-Options: nosniff'".to_string();
            f.cwe = Some("CWE-16".to_string());
            findings.push(f);
        }
        Some(v) if !v.eq_ignore_ascii_case("nosniff") => {
            let mut f = Finding::new(
                "X-Content-Type-Options incorrect value",
                Severity::Low,
                3.7,
                "infra",
                url,
                "GET",
            );
            f.description = format!("X-Content-Type-Options is '{}', expected 'nosniff'.", v);
            f.recommendation = "Set X-Content-Type-Options to exactly 'nosniff'".to_string();
            findings.push(f);
        }
        _ => {}
    }

    // X-Frame-Options
    if headers.get("x-frame-options").is_none() {
        let mut f = Finding::new(
            "X-Frame-Options missing",
            Severity::Low,
            3.7,
            "infra",
            url,
            "GET",
        );
        f.description =
            "The X-Frame-Options header is absent. The page may be embedded in iframes (clickjacking risk)."
                .to_string();
        f.recommendation = "Add 'X-Frame-Options: DENY' or set a Content-Security-Policy with frame-ancestors."
            .to_string();
        f.cwe = Some("CWE-1021".to_string());
        findings.push(f);
    }

    findings
}

fn check_server_disclosure(url: &str, headers: &reqwest::header::HeaderMap) -> Option<Finding> {
    let server = headers
        .get("server")
        .or_else(|| headers.get("x-powered-by"))?
        .to_str()
        .ok()?;

    // Only flag if version information is visible (contains digits after a slash or space)
    let looks_versioned = server.chars().any(|c| c.is_ascii_digit())
        && (server.contains('/') || server.contains(' '));

    if !looks_versioned {
        return None;
    }

    let mut f = Finding::new(
        "Server version disclosed in HTTP header",
        Severity::Informative,
        0.0,
        "infra",
        url,
        "GET",
    );
    f.description = format!(
        "The response header reveals server version information: '{}'. \
         This helps attackers enumerate vulnerable software versions.",
        server
    );
    f.recommendation =
        "Remove or sanitize the Server and X-Powered-By headers in your web server configuration."
            .to_string();
    f.cwe = Some("CWE-200".to_string());
    Some(f)
}

async fn probe_debug_endpoint(
    client: &HttpClient,
    url: &str,
    label: &str,
    severity_str: &str,
    cvss: f64,
) -> Option<Finding> {
    let req = client.inner().get(url).build().ok()?;
    let resp = client.send(req).await.ok()?;
    let status = resp.status().as_u16();

    // Only flag if endpoint responds with 200-299
    if !(200..300).contains(&status) {
        return None;
    }

    let severity = match severity_str {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    };

    let mut f = Finding::new(label, severity, cvss, "infra", url, "GET");
    f.description = format!(
        "The endpoint '{}' is publicly accessible (HTTP {}).",
        url, status
    );
    f.recommendation =
        "Restrict access to this endpoint. It should not be reachable from public networks."
            .to_string();
    f.proof = format!("GET {} → HTTP {}", url, status);
    Some(f)
}

fn extract_max_age(hsts: &str) -> Option<u64> {
    hsts.split(';')
        .map(|s| s.trim())
        .find(|s| s.to_lowercase().starts_with("max-age="))
        .and_then(|s| s["max-age=".len()..].parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_max_age_standard() {
        assert_eq!(
            extract_max_age("max-age=31536000; includeSubDomains"),
            Some(31_536_000)
        );
    }

    #[test]
    fn extract_max_age_only() {
        assert_eq!(extract_max_age("max-age=0"), Some(0));
    }

    #[test]
    fn extract_max_age_case_insensitive() {
        assert_eq!(extract_max_age("Max-Age=86400"), Some(86_400));
    }

    #[test]
    fn extract_max_age_missing() {
        assert_eq!(extract_max_age("includeSubDomains; preload"), None);
        assert_eq!(extract_max_age(""), None);
    }

    #[test]
    fn secret_patterns_non_empty() {
        assert!(!SECRET_PATTERNS.is_empty());
        assert!(SECRET_PATTERNS.iter().any(|(p, _, _)| *p == "api_key"));
    }

    #[test]
    fn stack_trace_patterns_non_empty() {
        assert!(!STACK_TRACE_PATTERNS.is_empty());
        assert!(STACK_TRACE_PATTERNS.iter().any(|&p| p.contains("traceback")));
    }

    #[test]
    fn check_secrets_detects_api_key() {
        let body = r#"{"api_key": "sk-prod-abc123", "data": []}"#;
        let findings = check_secrets_in_response("https://x.com/api", body);
        assert!(!findings.is_empty(), "should detect api_key");
        assert!(findings[0].title.contains("API Key"));
    }

    #[test]
    fn check_secrets_clean_response() {
        let body = r#"{"user": "alice", "email": "alice@example.com"}"#;
        let findings = check_secrets_in_response("https://x.com/api", body);
        assert!(findings.is_empty());
    }

    #[test]
    fn check_stack_traces_detects_php_error() {
        let body = "PHP Fatal error: Uncaught exception in /var/www/html/app.php on line 42";
        assert!(check_stack_traces("https://x.com/page", body).is_some());
    }

    #[test]
    fn check_stack_traces_clean_response() {
        let body = r#"{"status": "ok", "data": [1, 2, 3]}"#;
        assert!(check_stack_traces("https://x.com/api", body).is_none());
    }
}

// ---------------------------------------------------------------------------
// Phase 8 additions
// ---------------------------------------------------------------------------

// --- CSP ---

fn check_csp(url: &str, headers: &reqwest::header::HeaderMap) -> Option<Finding> {
    let csp = match headers.get("content-security-policy") {
        None => {
            let mut f = Finding::new(
                "Content-Security-Policy header missing",
                Severity::Medium,
                5.4,
                "infra",
                url,
                "GET",
            );
            f.description =
                "The Content-Security-Policy header is absent. Without CSP, the application \
                 is exposed to XSS and data injection attacks."
                    .to_string();
            f.recommendation =
                "Define a strict CSP: default-src 'self'; avoid 'unsafe-inline' and 'unsafe-eval'."
                    .to_string();
            f.cwe = Some("CWE-1021".to_string());
            f.references = vec![
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html".to_string(),
            ];
            return Some(f);
        }
        Some(v) => v.to_str().unwrap_or("").to_lowercase(),
    };

    // CSP present but contains dangerous directives
    let dangerous: Vec<&str> = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]
        .iter()
        .filter(|&&kw| csp.contains(kw))
        .copied()
        .collect();

    if !dangerous.is_empty() {
        let mut f = Finding::new(
            "Content-Security-Policy contains unsafe directives",
            Severity::Medium,
            5.4,
            "infra",
            url,
            "GET",
        );
        f.description = format!(
            "The CSP header contains potentially dangerous directives: {}. \
             These weaken XSS protection.",
            dangerous.join(", ")
        );
        f.recommendation =
            "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts."
                .to_string();
        f.cwe = Some("CWE-1021".to_string());
        f.references = vec![
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html".to_string(),
        ];
        return Some(f);
    }

    None
}

// --- Referrer-Policy ---

fn check_referrer_policy(url: &str, headers: &reqwest::header::HeaderMap) -> Option<Finding> {
    if headers.get("referrer-policy").is_some() {
        return None;
    }
    let mut f = Finding::new(
        "Referrer-Policy header missing",
        Severity::Low,
        3.1,
        "infra",
        url,
        "GET",
    );
    f.description =
        "The Referrer-Policy header is absent. The browser may leak the full URL \
         (including tokens or paths) in the Referer header to third-party sites."
            .to_string();
    f.recommendation =
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            .to_string();
    f.cwe = Some("CWE-200".to_string());
    Some(f)
}

// --- Cookie Flags ---

fn check_cookie_flags(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for value in headers.get_all("set-cookie") {
        let raw = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let lower = raw.to_lowercase();

        // Extract cookie name (first segment before '=')
        let name = raw.split('=').next().unwrap_or("?").trim();

        if !lower.contains("secure") && url.starts_with("https") {
            let mut f = Finding::new(
                format!("Cookie '{}' missing Secure flag", name),
                Severity::Medium,
                5.9,
                "infra",
                url,
                "GET",
            );
            f.description = format!(
                "The cookie '{}' is set without the Secure flag. It may be transmitted \
                 over unencrypted HTTP connections.",
                name
            );
            f.recommendation =
                "Add the Secure flag to all cookies set on HTTPS endpoints.".to_string();
            f.cwe = Some("CWE-614".to_string());
            f.references = vec![
                "https://owasp.org/www-community/controls/SecureCookieAttribute".to_string(),
            ];
            findings.push(f);
        }

        if !lower.contains("httponly") {
            let mut f = Finding::new(
                format!("Cookie '{}' missing HttpOnly flag", name),
                Severity::Medium,
                4.7,
                "infra",
                url,
                "GET",
            );
            f.description = format!(
                "The cookie '{}' is set without the HttpOnly flag. \
                 It is accessible via JavaScript and can be stolen by XSS.",
                name
            );
            f.recommendation =
                "Add the HttpOnly flag to all session and authentication cookies.".to_string();
            f.cwe = Some("CWE-1004".to_string());
            f.references = vec![
                "https://owasp.org/www-community/HttpOnly".to_string(),
            ];
            findings.push(f);
        }

        if !lower.contains("samesite") {
            let mut f = Finding::new(
                format!("Cookie '{}' missing SameSite attribute", name),
                Severity::Low,
                3.5,
                "infra",
                url,
                "GET",
            );
            f.description = format!(
                "The cookie '{}' has no SameSite attribute, exposing it to CSRF attacks.",
                name
            );
            f.recommendation =
                "Set SameSite=Strict or SameSite=Lax on all cookies.".to_string();
            f.cwe = Some("CWE-352".to_string());
            findings.push(f);
        }
    }

    findings
}

// --- TLS / HTTP without HTTPS ---

async fn check_tls(client: &HttpClient, base: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // If the target is already HTTP — no TLS at all
    if base.starts_with("http://") {
        let mut f = Finding::new(
            "API served over plain HTTP (no TLS)",
            Severity::Critical,
            9.8,
            "infra",
            base,
            "GET",
        );
        f.description =
            "The API is accessible over HTTP without TLS encryption. All traffic \
             (including credentials and tokens) is transmitted in cleartext."
                .to_string();
        f.recommendation =
            "Serve all API traffic exclusively over HTTPS (TLS 1.2+). Redirect HTTP → HTTPS \
             and set HSTS."
                .to_string();
        f.cwe = Some("CWE-319".to_string());
        f.references = vec![
            "https://owasp.org/www-project-api-security/".to_string(),
        ];
        findings.push(f);
        return findings;
    }

    // If HTTPS — check whether HTTP (non-TLS) is also accessible without a redirect
    if base.starts_with("https://") {
        let http_url = format!("http://{}", &base[8..]);
        let req = client.inner().get(&http_url).build();
        if let Ok(req) = req {
            // Use inner client directly so we don't follow redirects automatically
            let result = client
                .inner()
                .execute(req)
                .await;
            if let Ok(resp) = result {
                let status = resp.status().as_u16();
                // If the server returns 200 on HTTP instead of redirecting → finding
                if matches!(status, 200..=299) {
                    let mut f = Finding::new(
                        "API accessible over HTTP without HTTPS redirect",
                        Severity::High,
                        7.4,
                        "infra",
                        &http_url,
                        "GET",
                    );
                    f.description = format!(
                        "The HTTP endpoint {} returns HTTP {} without redirecting to HTTPS. \
                         Traffic can be intercepted by a man-in-the-middle attacker.",
                        http_url, status
                    );
                    f.proof = format!("GET {} → HTTP {}", http_url, status);
                    f.recommendation =
                        "Configure your server to return 301/308 for all HTTP requests \
                         and add HSTS to prevent future HTTP access."
                            .to_string();
                    f.cwe = Some("CWE-319".to_string());
                    findings.push(f);
                }
            }
        }
    }

    findings
}

// --- Secrets in response body ---

const SECRET_PATTERNS: &[(&str, &str, &str)] = &[
    // (pattern substring, label, CWE)
    ("api_key",      "API Key",           "CWE-312"),
    ("apikey",       "API Key",           "CWE-312"),
    ("api-key",      "API Key",           "CWE-312"),
    ("secret_key",   "Secret Key",        "CWE-312"),
    ("client_secret","OAuth Client Secret","CWE-312"),
    ("access_token", "Access Token",      "CWE-312"),
    ("private_key",  "Private Key",       "CWE-312"),
    ("password",     "Password",          "CWE-256"),
    ("passwd",       "Password",          "CWE-256"),
    ("db_password",  "DB Password",       "CWE-256"),
    ("aws_secret",   "AWS Secret",        "CWE-312"),
    ("AKIA",         "AWS Access Key ID", "CWE-312"),
];

fn check_secrets_in_response(url: &str, body: &str) -> Vec<Finding> {
    let lower = body.to_lowercase();
    let mut findings = Vec::new();
    let mut already_flagged = std::collections::HashSet::new();

    for &(pattern, label, cwe) in SECRET_PATTERNS {
        if lower.contains(pattern) && already_flagged.insert(label) {
            let mut f = Finding::new(
                format!("Sensitive data in response — {}", label),
                Severity::Critical,
                9.1,
                "infra",
                url,
                "GET",
            );
            f.description = format!(
                "The response body of {} appears to contain a {} (keyword: '{}'). \
                 Exposing secrets in API responses is a critical security risk.",
                url, label, pattern
            );
            f.proof = format!("Keyword '{}' found in response body", pattern);
            f.recommendation = format!(
                "Never return {} in API responses. Audit all serializers and response \
                 schemas to exclude sensitive fields.",
                label
            );
            f.cwe = Some(cwe.to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// --- Stack traces in response body ---

const STACK_TRACE_PATTERNS: &[&str] = &[
    "traceback (most recent call last)",
    "at java.",
    "at org.springframework",
    "at com.sun.",
    "exception in thread",
    "unhandledexception",
    "system.nullreferenceexception",
    "php fatal error",
    "php warning:",
    "php parse error",
    "warning: include(",
    "failed to open stream",
    "stack trace:",
    "panic: runtime error",
    "goroutine 1 [running]",
    "/var/www/",
    "/home/ubuntu/",
    "/usr/local/lib/",
    "app/controllers/",
    "app/models/",
];

fn check_stack_traces(url: &str, body: &str) -> Option<Finding> {
    let lower = body.to_lowercase();

    let matched = STACK_TRACE_PATTERNS
        .iter()
        .find(|&&p| lower.contains(p))?;

    let mut f = Finding::new(
        "Stack trace / internal path exposed in response",
        Severity::Medium,
        5.3,
        "infra",
        url,
        "GET",
    );
    f.description = format!(
        "The response of {} contains what appears to be a server-side stack trace or \
         internal file path (matched: '{}'). This leaks implementation details that \
         help attackers fingerprint and exploit the application.",
        url, matched
    );
    f.proof = format!("Pattern '{}' found in response body", matched);
    f.recommendation =
        "Disable detailed error messages in production. Return generic error responses \
         (HTTP 500) without internal details. Use structured logging instead."
            .to_string();
    f.cwe = Some("CWE-209".to_string());
    f.references = vec![
        "https://owasp.org/www-community/Improper_Error_Handling".to_string(),
    ];
    Some(f)
}
