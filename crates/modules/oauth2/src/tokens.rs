use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check 4: Token introspection non protégée
// ---------------------------------------------------------------------------

pub(super) async fn probe_introspect_unauth(
    client: &HttpClient,
    base: &str,
    introspect_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = introspect_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::INTROSPECT_PATHS.iter().map(|p| super::build_url(base, p)).collect()
    } else {
        spec_urls
    };

    let dummy_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummy";

    for url in &probe_urls {
        // POST without Authorization header
        let req = client
            .inner()
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("token={}", dummy_token))
            .build();

        let Ok(req) = req else { continue };
        let Ok(resp) = client.send(req).await else { continue };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // RFC 7662: unauthenticated introspection should return 401
        // If we get 200 with "active" field → vulnerability
        let exposed = status == 200
            && (body_lower.contains("\"active\"")
                || body_lower.contains("\"sub\"")
                || body_lower.contains("\"scope\""));

        if exposed {
            let mut f = Finding::new(
                format!("OAuth2 — Introspection de token non authentifiée — {}", url),
                Severity::High,
                7.5,
                "oauth2",
                url.clone(),
                "POST",
            );
            f.description =
                "L'endpoint d'introspection (RFC 7662) répond sans authentification. \
                 N'importe quel client peut vérifier la validité d'un token et lire ses claims \
                 (sujet, scopes, expiration) sans présenter de credentials."
                    .to_string();
            f.proof = format!(
                "POST {} sans Authorization → HTTP {} body: {}",
                url,
                status,
                body.chars().take(200).collect::<String>()
            );
            f.recommendation =
                "Protéger l'endpoint d'introspection par authentification client (Basic Auth \
                 ou bearer token). Seuls les resource servers enregistrés doivent pouvoir \
                 appeler cet endpoint. RFC 7662 Section 2.1 l'exige explicitement."
                    .to_string();
            f.cwe = Some("CWE-306".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc7662".to_string(),
                "https://portswigger.net/web-security/oauth".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check 5: Token endpoint acceptant GET (leak via logs/referrer)
// ---------------------------------------------------------------------------

pub(super) async fn probe_token_endpoint_methods(
    client: &HttpClient,
    base: &str,
    token_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = token_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        super::TOKEN_PATHS.iter().map(|p| super::build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        let test_url = format!(
            "{}?grant_type=authorization_code&code=test&redirect_uri=https%3A%2F%2Fexample.com",
            url
        );
        let Some((status, _body)) = super::get_text(client, &test_url).await else {
            continue;
        };

        // 200 or 400 (invalid_grant) but not 405 (method not allowed) means GET is accepted
        if status != 405 && status != 404 {
            let mut f = Finding::new(
                format!("OAuth2 — Token endpoint accepte GET (fuite potentielle) — {}", url),
                Severity::Low,
                3.7,
                "oauth2",
                url.clone(),
                "GET",
            );
            f.description =
                "L'endpoint de token répond aux requêtes GET. Les paramètres sensibles \
                 (code, client_secret) passés en query string peuvent être exposés dans les \
                 logs serveur, l'historique navigateur ou le header Referer."
                    .to_string();
            f.proof = format!("GET {} → HTTP {}", test_url, status);
            f.recommendation =
                "L'endpoint de token doit exclusivement accepter POST (RFC 6749 Section 3.2). \
                 Retourner 405 Method Not Allowed pour toute autre méthode. \
                 Ne jamais accepter client_secret dans la query string."
                    .to_string();
            f.cwe = Some("CWE-319".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check 6: JWKS endpoint public (information disclosure)
// ---------------------------------------------------------------------------

pub(super) async fn probe_open_jwks(client: &HttpClient, base: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in super::JWKS_PATHS {
        let url = super::build_url(base, path);
        let Some((status, body)) = super::get_text(client, &url).await else {
            continue;
        };

        if status == 200 && (body.contains("\"keys\"") || body.contains("\"kty\"")) {
            // JWKS public is expected — only flag if it exposes private keys
            if body.contains("\"d\"") || body.contains("\"p\"") || body.contains("\"q\"") {
                let mut f = Finding::new(
                    format!("OAuth2 — Clé privée exposée dans JWKS — {}", url),
                    Severity::Critical,
                    10.0,
                    "oauth2",
                    url.clone(),
                    "GET",
                );
                f.description =
                    "L'endpoint JWKS expose des paramètres de clé privée RSA/EC (d, p, q). \
                     Un attaquant peut forger des tokens JWT signés acceptés par le serveur."
                        .to_string();
                f.proof = format!(
                    "GET {} → HTTP {} — champs de clé privée trouvés (\"d\", \"p\" ou \"q\")",
                    url, status
                );
                f.recommendation =
                    "Le JWKS public ne doit exposer que les clés publiques. \
                     Vérifier immédiatement la configuration du serveur d'autorisation \
                     et révoquer toutes les clés compromises."
                        .to_string();
                f.cwe = Some("CWE-312".to_string());
                f.references = vec![
                    "https://datatracker.ietf.org/doc/html/rfc7517".to_string(),
                ];
                findings.push(f);
            }
        }
    }

    findings
}
