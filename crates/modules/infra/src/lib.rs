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
