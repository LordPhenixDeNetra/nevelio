use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{METHOD_BLOCKED_INDICATORS, METHOD_OVERRIDE_HEADERS};

// ---------------------------------------------------------------------------
// Check: HTTP Method Override (X-HTTP-Method-Override bypass)
// ---------------------------------------------------------------------------

pub(super) async fn check_method_override(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    // Only probe GET endpoints (we override to DELETE via header)
    if ep.method != "GET" {
        return vec![];
    }

    for (header_name, override_method) in METHOD_OVERRIDE_HEADERS {
        let mut builder = client
            .inner()
            .request(reqwest::Method::GET, &ep.full_url)
            .header(*header_name, *override_method);
        if !token.is_empty() {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }
        let Ok(req) = builder.build() else { continue };
        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap_or_default();
        let body_lower = String::from_utf8_lossy(&body).to_lowercase();

        let is_blocked = METHOD_BLOCKED_INDICATORS
            .iter()
            .any(|kw| body_lower.contains(kw));

        if matches!(status, 200 | 204) && !is_blocked {
            let mut f = Finding::new(
                format!(
                    "HTTP Method Override — {} accepté via `{}`",
                    override_method, header_name
                ),
                Severity::High,
                7.5,
                "access-control".to_string(),
                ep.full_url.clone(),
                "GET".to_string(),
            );
            f.description = format!(
                "L'endpoint {} accepte la méthode {} via le header `{}`. \
                 Un attaquant peut effectuer des actions destructrices (DELETE, PUT) \
                 en contournant les protections de méthode HTTP.",
                ep.full_url, override_method, header_name
            );
            f.proof = format!(
                "GET {} avec header `{}: {}` → HTTP {} (attendu 405 ou 403)",
                ep.full_url, header_name, override_method, status
            );
            f.recommendation =
                "Ignorer les headers de surcharge de méthode HTTP en production. \
                 Si nécessaire, n'autoriser que pour des clients authentifiés et tracer les usages."
                    .to_string();
            f.cwe = Some("CWE-650".to_string());
            f.references =
                vec!["https://portswigger.net/web-security/request-smuggling".to_string()];
            return vec![f];
        }
    }
    vec![]
}
