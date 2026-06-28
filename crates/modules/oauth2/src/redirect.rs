use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check 1: redirect_uri manipulation
// ---------------------------------------------------------------------------

pub(super) async fn probe_redirect_uri(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::AUTHORIZE_PATHS.iter().map(|p| super::build_url(base, p)).collect()
    } else {
        spec_urls
    };

    let malicious_redirects = [
        "https://evil.example.com/callback",
        "https://evil.com@legitimate.example.com/callback",
        "https://legitimate.example.com.evil.com/callback",
        "javascript:alert(1)",
        "//evil.example.com/callback",
    ];

    for url in &probe_urls {
        for redir in &malicious_redirects {
            let test_url = format!(
                "{}?response_type=code&client_id=test&redirect_uri={}&scope=openid",
                url,
                super::urlenc(redir)
            );
            let Some((status, body)) = super::get_text(client, &test_url).await else {
                continue;
            };

            // Server accepted the malicious redirect_uri without error
            let vulnerable = status == 302
                || (status == 200
                    && !body.to_lowercase().contains("invalid_redirect_uri")
                    && !body.to_lowercase().contains("redirect_uri_mismatch")
                    && !body.to_lowercase().contains("error"));

            if vulnerable {
                let mut f = Finding::new(
                    format!("OAuth2 redirect_uri Open Redirect — {}", url),
                    Severity::High,
                    8.1,
                    "oauth2",
                    url.clone(),
                    "GET",
                );
                f.description =
                    "Le serveur d'autorisation accepte un redirect_uri non enregistré. \
                     Un attaquant peut voler le code d'autorisation en faisant cliquer une victime \
                     sur un lien OAuth2 malveillant."
                        .to_string();
                f.proof = format!(
                    "redirect_uri={} → HTTP {} (pas d'erreur invalid_redirect_uri)",
                    redir, status
                );
                f.recommendation =
                    "Enregistrer et valider strictement les redirect_uri autorisées côté serveur. \
                     Rejeter toute valeur non exactement enregistrée (comparaison stricte, pas de wildcards). \
                     RFC 6749 Section 3.1.2 interdit les redirections non enregistrées."
                        .to_string();
                f.cwe = Some("CWE-601".to_string());
                f.references = vec![
                    "https://portswigger.net/web-security/oauth".to_string(),
                    "https://datatracker.ietf.org/doc/html/rfc6749#section-10.6".to_string(),
                ];
                findings.push(f);
                break; // one finding per endpoint
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check 2: Missing state parameter (CSRF)
// ---------------------------------------------------------------------------

pub(super) async fn probe_missing_state(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::AUTHORIZE_PATHS.iter().map(|p| super::build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        // Request without state parameter
        let test_url = format!(
            "{}?response_type=code&client_id=test&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid",
            url
        );
        let Some((status, body)) = super::get_text(client, &test_url).await else {
            continue;
        };

        // Server returns auth page (200/302) without complaining about missing state
        let body_lower = body.to_lowercase();
        let accepts_no_state = (status == 200 || status == 302)
            && !body_lower.contains("state_required")
            && !body_lower.contains("invalid_request")
            && body_lower.len() > 100;

        if accepts_no_state {
            let mut f = Finding::new(
                format!("OAuth2 — Paramètre `state` absent accepté (CSRF) — {}", url),
                Severity::Medium,
                6.1,
                "oauth2",
                url.clone(),
                "GET",
            );
            f.description =
                "Le serveur d'autorisation n'exige pas le paramètre `state`. \
                 Sans ce paramètre anti-CSRF, un attaquant peut initier un flow OAuth2 \
                 et tromper un utilisateur pour qu'il lie son compte à un compte contrôlé par l'attaquant."
                    .to_string();
            f.proof = format!(
                "Requête sans state → HTTP {} (pas d'erreur state_required)",
                status
            );
            f.recommendation =
                "Exiger et valider le paramètre `state` sur chaque requête d'autorisation. \
                 Utiliser une valeur aléatoire cryptographiquement forte (≥128 bits), \
                 liée à la session utilisateur. Rejeter les requêtes sans state valide."
                    .to_string();
            f.cwe = Some("CWE-352".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc6749#section-10.12".to_string(),
                "https://portswigger.net/web-security/csrf/bypassing-token-validation".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check 3: PKCE bypass (code_challenge absent accepté)
// ---------------------------------------------------------------------------

pub(super) async fn probe_pkce_bypass(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::AUTHORIZE_PATHS.iter().map(|p| super::build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        // Requête qui devrait exiger PKCE mais ne fournit pas code_challenge
        let test_url = format!(
            "{}?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid&state=random123",
            url
        );
        let Some((status, body)) = super::get_text(client, &test_url).await else {
            continue;
        };

        let body_lower = body.to_lowercase();
        // Server accepted the request without code_challenge
        let pkce_not_required = (status == 200 || status == 302)
            && !body_lower.contains("code_challenge_required")
            && !body_lower.contains("invalid_request")
            && body_lower.len() > 100;

        if pkce_not_required {
            let mut f = Finding::new(
                format!("OAuth2 — PKCE non imposé pour clients publics — {}", url),
                Severity::Medium,
                6.5,
                "oauth2",
                url.clone(),
                "GET",
            );
            f.description =
                "Le serveur d'autorisation n'impose pas PKCE (RFC 7636) pour les clients publics. \
                 Un attaquant interceptant le code d'autorisation (via browser history, logs, referrer) \
                 peut l'échanger contre un token sans posséder le code_verifier."
                    .to_string();
            f.proof = format!(
                "Requête sans code_challenge → HTTP {} (pas d'erreur code_challenge_required)",
                status
            );
            f.recommendation =
                "Imposer PKCE (code_challenge_method=S256) pour tous les clients publics (SPA, mobile). \
                 Rejeter les requêtes d'autorisation sans code_challenge pour ces clients. \
                 RFC 9700 (OAuth 2.1) rend PKCE obligatoire pour tous les clients."
                    .to_string();
            f.cwe = Some("CWE-287".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc7636".to_string(),
                "https://oauth.net/2/pkce/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}
