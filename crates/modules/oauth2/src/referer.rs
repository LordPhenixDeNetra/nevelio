use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check 10: Token leakage via URL / Referer header (response_mode=query)
// ---------------------------------------------------------------------------

pub(super) async fn probe_token_referer_leak(
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

    // Test 1: response_mode=query — server puts token in the URL query string
    // (token would appear in server logs, browser history, Referer headers)
    for url in &probe_urls {
        let test_url = format!(
            "{}?response_type=token&response_mode=query&client_id=nevelio_test&redirect_uri={}",
            url,
            super::urlenc("https://nevelio.example.com/callback")
        );
        let Some((status, body)) = super::get_text(client, &test_url).await else { continue };

        // Check if the server responds with a token in URL (redirect Location header)
        // or directly in the body with a query-string format
        let location_has_token = body.contains("access_token=") || body.contains("token=");
        let redirect_with_query = matches!(status, 302 | 303 | 307 | 308) && body.contains("access_token");

        if location_has_query_token(status, &body) || redirect_with_query || location_has_token {
            let mut f = Finding::new(
                format!("OAuth2 — Token d'accès exposé dans l'URL (response_mode=query) — {}", url),
                Severity::Medium,
                6.5,
                "oauth2",
                url.clone(),
                "GET",
            );
            f.description =
                "Le serveur d'autorisation semble supporter `response_mode=query`, ce qui place \
                 le token d'accès directement dans la query string de l'URL de redirection. \
                 Ce token apparaît dans les logs serveur, l'historique du navigateur et est \
                 envoyé dans le header `Referer` lors de la navigation vers des ressources tierces."
                    .to_string();
            f.proof = format!("GET {} → HTTP {} — token détecté dans la réponse", test_url, status);
            f.recommendation =
                "Utiliser uniquement `response_mode=fragment` pour les tokens (token dans #fragment, \
                 non envoyé au serveur) ou `response_mode=form_post` pour les codes d'autorisation. \
                 Rejeter explicitement `response_mode=query` pour les flux retournant des tokens."
                    .to_string();
            f.cwe = Some("CWE-598".to_string());
            f.references = vec![
                "https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html".to_string(),
                "https://datatracker.ietf.org/doc/html/rfc6749#section-10.3".to_string(),
            ];
            findings.push(f);
            break;
        }
    }

    // Test 2: Does the token endpoint return access_token as URL param (not body)?
    for path in super::TOKEN_PATHS {
        let url = super::build_url(base, path);
        let body_str = "grant_type=client_credentials&client_id=nevelio_test&client_secret=test";
        let Ok(req) = client
            .inner()
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body_str)
            .build()
        else {
            continue;
        };
        let Ok(resp) = client.send(req).await else { continue };
        let status = resp.status().as_u16();
        // If redirected with token in URL
        if matches!(status, 302 | 303) {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                if loc.contains("access_token=") || loc.contains("token=") {
                    let mut f = Finding::new(
                        format!("OAuth2 — Token d'accès dans le header Location — {}", url),
                        Severity::High,
                        7.5,
                        "oauth2",
                        url.clone(),
                        "POST",
                    );
                    f.description =
                        "Le token endpoint redirige avec le token d'accès dans l'URL \
                         (header Location). Ce token sera capturé par les logs d'accès \
                         du serveur et transmis aux tiers via le header Referer."
                            .to_string();
                    f.proof = format!(
                        "POST {} → HTTP {} Location: {}",
                        url,
                        status,
                        &loc[..loc.len().min(200)]
                    );
                    f.recommendation =
                        "Le token endpoint doit toujours retourner les tokens dans le corps \
                         JSON de la réponse (application/json), jamais dans une URL de redirection."
                            .to_string();
                    f.cwe = Some("CWE-598".to_string());
                    findings.push(f);
                    break;
                }
            }
        }
        break; // Only test first token path
    }

    findings
}

pub(super) fn location_has_query_token(status: u16, body: &str) -> bool {
    matches!(status, 200) && body.contains("access_token") && body.contains("?access_token=")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::{OAuth2Module, collect_matching, build_url, urlenc, AUTHORIZE_PATHS};
    use nevelio_core::AttackModule;
    use nevelio_core::types::Endpoint;

    #[test]
    fn oauth2_module_name() {
        assert_eq!(OAuth2Module.name(), "oauth2");
    }

    #[test]
    fn urlenc_encodes_special_chars() {
        let encoded = urlenc("https://evil.example.com/callback?foo=bar");
        assert!(encoded.contains("%3A"), "colon: {encoded}");
        assert!(encoded.contains("%2F"), "slash: {encoded}");
        assert!(encoded.contains("%3F"), "question mark: {encoded}");
        assert!(encoded.contains("%3D"), "equals: {encoded}");
    }

    #[test]
    fn build_url_strips_trailing_slash() {
        assert_eq!(
            build_url("https://api.example.com/", "/oauth/authorize"),
            "https://api.example.com/oauth/authorize"
        );
    }

    #[test]
    fn build_url_no_double_slash() {
        let u = build_url("https://api.example.com", "/token");
        assert_eq!(u, "https://api.example.com/token");
        assert!(!u.contains("//token"));
    }

    #[test]
    fn authorize_paths_non_empty() {
        assert!(!AUTHORIZE_PATHS.is_empty());
        assert!(AUTHORIZE_PATHS.contains(&"/oauth/authorize"));
    }

    #[test]
    fn collect_matching_finds_oauth_endpoints() {
        let endpoints = vec![
            Endpoint {
                method: "GET".to_string(),
                path: "/oauth/authorize".to_string(),
                full_url: "https://api.example.com/oauth/authorize".to_string(),
                parameters: vec![],
                auth_required: false,
            },
            Endpoint {
                method: "GET".to_string(),
                path: "/users".to_string(),
                full_url: "https://api.example.com/users".to_string(),
                parameters: vec![],
                auth_required: true,
            },
        ];

        let matched = collect_matching(&endpoints, AUTHORIZE_PATHS);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].path, "/oauth/authorize");
    }
}
