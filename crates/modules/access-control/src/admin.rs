use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check: Unprotected admin endpoints (no authentication required)
// ---------------------------------------------------------------------------

pub(super) async fn check_admin_endpoints_unauth(
    client: &HttpClient,
    base_target: &str,
    admin_paths: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = base_target.trim_end_matches('/');

    for path in admin_paths {
        let url = format!("{}{}", base, path);
        let Ok(req) = client.inner().get(&url).build() else { continue };
        let Ok(resp) = client.send(req).await else { continue };

        let status = resp.status().as_u16();

        if matches!(status, 200..=299) {
            let mut f = Finding::new(
                format!("Endpoint admin non protégé — {}", path),
                Severity::High,
                7.5,
                "access-control".to_string(),
                url.clone(),
                "GET".to_string(),
            );
            f.description = format!(
                "L'endpoint d'administration {} est accessible sans aucune authentification \
                 (HTTP {}). N'importe qui peut y accéder depuis internet.",
                url, status
            );
            f.proof = format!("GET {} sans Authorization → HTTP {}", url, status);
            f.recommendation =
                "Protéger tous les endpoints d'administration par une authentification forte. \
                 Restreindre l'accès par IP (allowlist réseau). \
                 Ne pas exposer les endpoints de monitoring/debug sur des ports publics."
                    .to_string();
            f.cwe = Some("CWE-284".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }
    findings
}
