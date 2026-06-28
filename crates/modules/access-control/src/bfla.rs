use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{get_with_token, ALL_METHODS, BFLA_ERROR_INDICATORS};

// ---------------------------------------------------------------------------
// Check: BFLA — Broken Function Level Authorization
// ---------------------------------------------------------------------------

pub(super) async fn check_bfla(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for method in ALL_METHODS {
        if method.eq_ignore_ascii_case(&ep.method) {
            continue; // skip the documented method
        }

        let Some((status, body)) = get_with_token(client, &ep.full_url, method, token).await else {
            continue;
        };

        if matches!(status, 200..=299) {
            let body_lower = String::from_utf8_lossy(&body).to_lowercase();
            let is_real_error = BFLA_ERROR_INDICATORS
                .iter()
                .any(|kw| body_lower.contains(kw));
            if is_real_error {
                continue;
            }

            let mut f = Finding::new(
                format!("BFLA — méthode {} non documentée acceptée", method),
                Severity::High,
                7.5,
                "access-control".to_string(),
                ep.full_url.clone(),
                method.to_string(),
            );
            f.description = format!(
                "L'endpoint {} n'est documenté que pour {} mais accepte la méthode {} \
                 avec un HTTP {}. Un attaquant peut effectuer des actions non autorisées.",
                ep.full_url, ep.method, method, status
            );
            f.proof = format!(
                "{} {} → HTTP {} (endpoint documenté comme {} uniquement)",
                method, ep.full_url, status, ep.method
            );
            f.recommendation =
                "Configurer une allowlist stricte des méthodes HTTP autorisées sur chaque \
                 endpoint. Retourner 405 Method Not Allowed pour toute méthode non prévue."
                    .to_string();
            f.cwe = Some("CWE-285".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check: Vertical Privilege Escalation (admin paths)
// ---------------------------------------------------------------------------

pub(super) async fn check_vertical_privesc(
    client: &HttpClient,
    base_target: &str,
    token: &str,
    admin_paths: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = base_target.trim_end_matches('/');

    for path in admin_paths {
        let url = format!("{}{}", base, path);
        let Some((status, _)) = get_with_token(client, &url, "GET", token).await else {
            continue;
        };

        if matches!(status, 200..=299) {
            let mut f = Finding::new(
                format!("Privilege Escalation Verticale — {}", path),
                Severity::Critical,
                9.1,
                "access-control".to_string(),
                url.clone(),
                "GET".to_string(),
            );
            f.description = format!(
                "L'endpoint d'administration {} est accessible avec un token utilisateur standard \
                 (HTTP {}). Un utilisateur non-admin peut accéder à des fonctions privilégiées.",
                url, status
            );
            f.proof = format!("GET {} avec token fourni → HTTP {}", url, status);
            f.recommendation =
                "Implémenter un contrôle de rôle côté serveur sur tous les endpoints admin. \
                 Ne pas se fier uniquement à l'obscurité des URLs."
                    .to_string();
            f.cwe = Some("CWE-269".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}
