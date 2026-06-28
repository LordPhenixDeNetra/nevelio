use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check: Basic Auth weak credentials
// ---------------------------------------------------------------------------

pub(super) async fn check_basic_auth(client: &HttpClient, ep: &Endpoint) -> Vec<Finding> {
    let probe = match client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .build()
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let Ok(probe_resp) = client.send(probe).await else {
        return vec![];
    };

    let www_auth = probe_resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !www_auth.contains("basic") {
        return vec![];
    }

    for (user, pass) in super::COMMON_BASIC_CREDS {
        let req = match client
            .inner()
            .request(
                ep.method.parse().unwrap_or(reqwest::Method::GET),
                &ep.full_url,
            )
            .basic_auth(user, Some(pass))
            .build()
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "Weak Basic Auth Credentials".to_string(),
                Severity::High,
                8.8,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "HTTP Basic Authentication on {} accepts trivial credentials. \
                 An attacker can gain access through a simple dictionary attack.",
                ep.full_url
            );
            f.proof = format!(
                "Login succeeded with {}:{} → HTTP {}",
                user,
                pass,
                resp.status().as_u16()
            );
            f.recommendation =
                "Enforce strong password policies and account lockout. Prefer token-based \
                 authentication (OAuth 2.0 / JWT) over Basic Auth."
                    .to_string();
            f.cwe = Some("CWE-521".to_string());
            f.references = vec![
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}
