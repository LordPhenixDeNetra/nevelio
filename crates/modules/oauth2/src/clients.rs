use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check 9: Client ID enumeration
// ---------------------------------------------------------------------------

const COMMON_CLIENT_IDS: &[&str] = &[
    "app", "client", "mobile", "web", "spa", "api", "default", "test", "admin", "demo", "dev",
    "prod", "frontend", "backend", "android", "ios", "native", "public", "internal",
];

pub(super) async fn probe_client_enumeration(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::AUTHORIZE_PATHS
            .iter()
            .map(|p| super::build_url(base, p))
            .collect()
    } else {
        spec_urls
    };

    // Baseline: try an obviously invalid client_id and note the response
    let invalid_url = format!(
        "{}?response_type=code&client_id=nevelio_definitely_invalid_xxxx&redirect_uri={}",
        probe_urls
            .first()
            .unwrap_or(&super::build_url(base, super::AUTHORIZE_PATHS[0])),
        super::urlenc("https://nevelio.example.com/callback")
    );
    let baseline = super::get_text(client, &invalid_url).await;
    let baseline_status = baseline.as_ref().map(|(s, _)| *s).unwrap_or(404);

    let mut found_clients: Vec<String> = Vec::new();

    for url in &probe_urls {
        for client_id in COMMON_CLIENT_IDS {
            let test_url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}",
                url,
                client_id,
                super::urlenc("https://nevelio.example.com/callback")
            );
            let Some((status, body)) = super::get_text(client, &test_url).await else {
                continue;
            };
            let body_lower = body.to_lowercase();

            // A valid client_id produces a different response than an invalid one:
            // - redirect to login page (302) instead of error (400)
            // - body contains "login", "sign in", or "consent" (not "invalid_client")
            let likely_valid = status != baseline_status
                && !body_lower.contains("invalid_client")
                && !body_lower.contains("client not found")
                && (matches!(status, 200 | 302)
                    || body_lower.contains("login")
                    || body_lower.contains("consent")
                    || body_lower.contains("sign in"));

            if likely_valid {
                found_clients.push(client_id.to_string());
            }

            if found_clients.len() >= 3 {
                break; // enough evidence
            }
        }
        if !found_clients.is_empty() {
            break;
        }
    }

    if !found_clients.is_empty() {
        let url = probe_urls.first().cloned().unwrap_or_default();
        let mut f = Finding::new(
            "OAuth2 — Enumération de client_id prévisible",
            Severity::Medium,
            5.3,
            "oauth2",
            url,
            "GET",
        );
        f.description = format!(
            "Des identifiants client OAuth2 prévisibles ont produit des réponses différentes \
             d'un client invalide, indiquant qu'ils sont enregistrés : {}. \
             Un attaquant peut énumérer les applications clientes et tenter des attaques \
             de phishing ou de token theft ciblées.",
            found_clients.join(", ")
        );
        f.recommendation =
            "Utiliser des client_ids non prédictibles (UUIDs v4 ou chaînes aléatoires). \
             Retourner des messages d'erreur identiques pour les clients valides et invalides \
             afin d'éviter l'énumération."
                .to_string();
        f.cwe = Some("CWE-203".to_string());
        findings.push(f);
    }

    findings
}
