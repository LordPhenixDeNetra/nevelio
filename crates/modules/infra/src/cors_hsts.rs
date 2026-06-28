use nevelio_core::types::{Finding, Severity};
use reqwest::header::HeaderMap;

pub(super) fn check_cors(url: &str, headers: &HeaderMap) -> Option<Finding> {
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

pub(super) fn check_hsts(url: &str, headers: &HeaderMap) -> Option<Finding> {
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

pub(super) fn extract_max_age(hsts: &str) -> Option<u64> {
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
}
