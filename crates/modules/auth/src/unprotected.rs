use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check: Missing Authentication
// ---------------------------------------------------------------------------

pub(super) async fn check_unprotected_endpoint(
    client: &HttpClient,
    ep: &Endpoint,
    auth_token: &Option<String>,
) -> Vec<Finding> {
    if !ep.auth_required && auth_token.is_none() {
        return vec![];
    }

    let req = match client
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

    let Ok(resp) = client.send(req).await else {
        return vec![];
    };

    if resp.status().is_success() {
        let mut f = Finding::new(
            "Missing Authentication".to_string(),
            Severity::Critical,
            9.8,
            "auth".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description = format!(
            "The endpoint {} {} is accessible without an Authorization header. \
             Authentication is either absent or not enforced.",
            ep.method, ep.full_url
        );
        f.proof = format!("HTTP {} without credentials", resp.status().as_u16());
        f.recommendation =
            "Require a valid authentication token on all sensitive endpoints.".to_string();
        f.cwe = Some("CWE-306".to_string());
        f.references = vec![
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                .to_string(),
        ];
        return vec![f];
    }

    vec![]
}
