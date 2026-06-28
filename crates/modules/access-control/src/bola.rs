use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{extract_numeric_id, get_with_token, ALL_METHODS, BFLA_ERROR_INDICATORS};

// ---------------------------------------------------------------------------
// Check: BOLA — Broken Object Level Authorization (cross-verb)
// ---------------------------------------------------------------------------

pub(super) async fn check_bola(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    // Only endpoints that have a resource ID in the path
    let Some((prefix, id, suffix)) = extract_numeric_id(&ep.full_url) else {
        return vec![];
    };

    // Baseline: own resource with GET
    let own_url = &ep.full_url;
    let Some((baseline_status, baseline_body)) =
        get_with_token(client, own_url, "GET", token).await
    else {
        return vec![];
    };

    if !matches!(baseline_status, 200..=299) {
        return vec![];
    }

    // Try a different ID with each verb to detect cross-user access
    let other_id = if id == 1 { 2u64 } else { 1u64 };
    let other_url = format!("{}/{}{}", prefix, other_id, suffix);

    for method in ALL_METHODS {
        let Some((status, body)) = get_with_token(client, &other_url, method, token).await else {
            continue;
        };

        if matches!(status, 200..=299) && body != baseline_body && !body.is_empty() {
            let body_lower = String::from_utf8_lossy(&body).to_lowercase();
            let is_error = BFLA_ERROR_INDICATORS.iter().any(|kw| body_lower.contains(kw));
            if is_error { continue; }

            let mut f = Finding::new(
                format!("BOLA — {} /{}/ via {}", ep.path, other_id, method),
                Severity::High,
                8.1,
                "access-control".to_string(),
                other_url.clone(),
                method.to_string(),
            );
            f.description = format!(
                "L'endpoint {} accepte la méthode {} sur l'ID {} (autre que l'ID propriétaire {}) \
                 et retourne HTTP {}. Un attaquant peut accéder ou modifier les ressources d'autres utilisateurs.",
                ep.full_url, method, other_id, id, status
            );
            f.proof = format!(
                "{} {} → HTTP {} ({} octets) — ID substitué : {} → {}",
                method, other_url, status, body.len(), id, other_id
            );
            f.recommendation =
                "Vérifier côté serveur que la ressource demandée appartient à l'utilisateur \
                 authentifié pour chaque méthode HTTP. Implémenter un middleware de contrôle d'accès \
                 centralisé basé sur le token."
                    .to_string();
            f.cwe = Some("CWE-639".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}
