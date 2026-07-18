use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;
use reqwest::header::HeaderMap;

pub(super) fn check_security_headers(url: &str, headers: &HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    // X-Content-Type-Options
    match headers
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
    {
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
        f.recommendation =
            "Add 'X-Frame-Options: DENY' or set a Content-Security-Policy with frame-ancestors."
                .to_string();
        f.cwe = Some("CWE-1021".to_string());
        findings.push(f);
    }

    findings
}

pub(super) fn check_server_disclosure(url: &str, headers: &HeaderMap) -> Option<Finding> {
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

pub(super) async fn probe_debug_endpoint(
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

pub(super) fn check_csp(url: &str, headers: &HeaderMap) -> Option<Finding> {
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

pub(super) fn check_referrer_policy(url: &str, headers: &HeaderMap) -> Option<Finding> {
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
    f.description = "The Referrer-Policy header is absent. The browser may leak the full URL \
         (including tokens or paths) in the Referer header to third-party sites."
        .to_string();
    f.recommendation =
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.".to_string();
    f.cwe = Some("CWE-200".to_string());
    Some(f)
}
