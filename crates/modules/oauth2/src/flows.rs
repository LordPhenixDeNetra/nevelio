use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check 7: Implicit flow (response_type=token)
// ---------------------------------------------------------------------------

pub(super) async fn probe_implicit_flow(
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
        let test_url = format!(
            "{}?response_type=token&client_id=nevelio_test&redirect_uri={}&scope=openid",
            url,
            super::urlenc("https://nevelio.example.com/callback")
        );
        let Some((status, body)) = super::get_text(client, &test_url).await else { continue };

        // If the server returns a redirect with #access_token or a JSON with token_type,
        // the implicit flow is likely supported.
        let implicit_indicators = [
            "access_token", "#token", "token_type", "Bearer",
            // Some servers redirect to the callback with fragment
            "nevelio.example.com",
        ];
        let body_lower = body.to_lowercase();
        let supported = matches!(status, 302 | 303 | 307 | 308)
            || implicit_indicators.iter().any(|i| body_lower.contains(&i.to_lowercase()));

        if supported && !matches!(status, 400 | 401 | 403 | 404 | 405 | 501) {
            let mut f = Finding::new(
                format!("OAuth2 — Flow Implicit activé (response_type=token) — {}", url),
                Severity::Medium,
                5.4,
                "oauth2",
                url.clone(),
                "GET",
            );
            f.description =
                "L'endpoint d'autorisation OAuth2 semble accepter `response_type=token` (flux Implicit). \
                 Ce flux est déprécié par OAuth 2.1 car le token d'accès est exposé dans le fragment \
                 d'URL (#access_token=...) et peut être capturé via le header Referer, l'historique \
                 du navigateur, ou des scripts tiers."
                    .to_string();
            f.proof = format!("GET {} → HTTP {}", test_url, status);
            f.recommendation =
                "Désactiver le flux Implicit. Utiliser Authorization Code avec PKCE (RFC 7636) \
                 à la place. Configurer `response_type=code` comme seul mode autorisé."
                    .to_string();
            f.cwe = Some("CWE-200".to_string());
            f.references = vec![
                "https://oauth.net/2/grant-types/implicit/".to_string(),
                "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.2".to_string(),
            ];
            findings.push(f);
            break; // one finding per target
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check 8: Authorization code replay
// ---------------------------------------------------------------------------

pub(super) async fn probe_code_replay(
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

    let replay_code = "nevelio_replay_code_test_12345";
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id=nevelio_test",
        replay_code,
        super::urlenc("https://nevelio.example.com/callback")
    );

    for url in &probe_urls {
        // Send the same code twice; the second attempt should always fail.
        let mut responses = Vec::new();
        for _ in 0..2 {
            if let Some(Ok(req)) = Some(
                client
                    .inner()
                    .post(url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body.clone())
                    .build(),
            ) {
                if let Ok(resp) = client.send(req).await {
                    let status = resp.status().as_u16();
                    let rb = resp.text().await.unwrap_or_default();
                    responses.push((status, rb));
                }
            }
        }

        if responses.len() < 2 {
            continue;
        }

        let (s1, b1) = &responses[0];
        let (s2, b2) = &responses[1];

        // If both responses are identical 200/400(invalid_grant NOT present)
        // and neither contains "invalid_grant" or "code_reused", flag it.
        let first_is_ok = *s1 == 200 || b1.contains("access_token");
        let second_is_ok = *s2 == 200 || b2.contains("access_token");
        let second_rejected = b2.contains("invalid_grant")
            || b2.contains("code_reused")
            || b2.contains("already used")
            || *s2 == 400
            || *s2 == 401;

        if first_is_ok && second_is_ok && !second_rejected {
            let mut f = Finding::new(
                format!("OAuth2 — Code d'autorisation rejouable (replay) — {}", url),
                Severity::High,
                8.1,
                "oauth2",
                url.clone(),
                "POST",
            );
            f.description =
                "Le token endpoint accepte deux fois le même `authorization_code`. \
                 RFC 6749 §4.1.3 impose que les codes d'autorisation soient à usage unique : \
                 un attaquant qui intercepte un code peut l'utiliser en parallèle de la victime."
                    .to_string();
            f.proof = format!(
                "1er appel: HTTP {} — 2ème appel: HTTP {} (attendu: 400 invalid_grant)",
                s1, s2
            );
            f.recommendation =
                "Invalider immédiatement le code d'autorisation après sa première utilisation. \
                 Rejeter tout second usage avec `error: invalid_grant`. \
                 Utiliser des codes à usage unique avec un TTL court (< 60 secondes, RFC 6749)."
                    .to_string();
            f.cwe = Some("CWE-294".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3".to_string(),
            ];
            findings.push(f);
            break;
        }
    }

    findings
}
