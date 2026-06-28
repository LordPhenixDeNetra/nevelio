use nevelio_core::types::{Finding, Severity};

pub(super) const SECRET_PATTERNS: &[(&str, &str, &str)] = &[
    // (pattern substring, label, CWE)
    ("api_key",       "API Key",            "CWE-312"),
    ("apikey",        "API Key",            "CWE-312"),
    ("api-key",       "API Key",            "CWE-312"),
    ("secret_key",    "Secret Key",         "CWE-312"),
    ("client_secret", "OAuth Client Secret","CWE-312"),
    ("access_token",  "Access Token",       "CWE-312"),
    ("private_key",   "Private Key",        "CWE-312"),
    ("password",      "Password",           "CWE-256"),
    ("passwd",        "Password",           "CWE-256"),
    ("db_password",   "DB Password",        "CWE-256"),
    ("aws_secret",    "AWS Secret",         "CWE-312"),
    ("AKIA",          "AWS Access Key ID",  "CWE-312"),
];

pub(super) const STACK_TRACE_PATTERNS: &[&str] = &[
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

pub(super) fn check_secrets_in_response(url: &str, body: &str) -> Vec<Finding> {
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

pub(super) fn check_stack_traces(url: &str, body: &str) -> Option<Finding> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
