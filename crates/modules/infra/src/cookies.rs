use nevelio_core::types::{Finding, Severity};
use reqwest::header::HeaderMap;

pub(super) fn check_cookie_flags(url: &str, headers: &HeaderMap) -> Vec<Finding> {
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
            f.references =
                vec!["https://owasp.org/www-community/controls/SecureCookieAttribute".to_string()];
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
            f.references = vec!["https://owasp.org/www-community/HttpOnly".to_string()];
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
            f.recommendation = "Set SameSite=Strict or SameSite=Lax on all cookies.".to_string();
            f.cwe = Some("CWE-352".to_string());
            findings.push(f);
        }
    }

    findings
}
