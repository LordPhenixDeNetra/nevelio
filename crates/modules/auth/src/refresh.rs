use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

// ---------------------------------------------------------------------------
// Check: Refresh token replay / rotation not enforced
// ---------------------------------------------------------------------------

const REFRESH_TOKEN_PATHS: &[&str] = &[
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/connect/token",
    "/token",
    "/api/token",
    "/v1/oauth/token",
    "/v2/oauth/token",
];

pub(super) async fn check_refresh_token_replay(
    client: &HttpClient,
    base: &str,
) -> Vec<Finding> {
    let base = base.trim_end_matches('/');
    let fake_refresh = "nevelio_fake_refresh_token_replay_test_0000000";
    let body = format!("grant_type=refresh_token&refresh_token={}", fake_refresh);

    for path in REFRESH_TOKEN_PATHS {
        let url = format!("{}{}", base, path);
        let mut responses: Vec<(u16, String)> = Vec::new();

        for _ in 0..2 {
            let Ok(req) = client
                .inner()
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.clone())
                .build()
            else {
                continue;
            };
            let Ok(resp) = client.send(req).await else {
                continue;
            };
            responses.push((resp.status().as_u16(), resp.text().await.unwrap_or_default()));
        }

        if responses.len() < 2 {
            continue;
        }

        let (s1, b1) = &responses[0];
        let (s2, b2) = &responses[1];

        let both_ok = (*s1 == 200 || b1.contains("access_token"))
            && (*s2 == 200 || b2.contains("access_token"));
        let no_rotation = *s1 == 200
            && !b2.contains("invalid_grant")
            && !b2.contains("token_revoked")
            && !b2.contains("already_used");

        if both_ok || no_rotation {
            let mut f = Finding::new(
                format!("Auth — Refresh token rejouable sans invalidation — {}", url),
                Severity::High,
                7.5,
                "auth",
                url.clone(),
                "POST",
            );
            f.description =
                "Le token endpoint semble accepter plusieurs fois le même refresh token \
                 sans l'invalider après usage. Un attaquant qui obtient un refresh token \
                 peut générer de nouveaux access tokens indéfiniment."
                    .to_string();
            f.proof = format!(
                "1er appel: HTTP {} — 2ème appel avec le même token: HTTP {} \
                 (attendu: 400 invalid_grant après rotation)",
                s1, s2
            );
            f.recommendation =
                "Invalider le refresh token après chaque usage et révoquer toute la chaîne \
                 si un token déjà utilisé est présenté à nouveau (RFC 6819 §5.2.2.3)."
                    .to_string();
            f.cwe = Some("CWE-294".to_string());
            f.references = vec![
                "https://datatracker.ietf.org/doc/html/rfc6819#section-5.2.2.3".to_string(),
            ];
            return vec![f];
        }

        // Token endpoint rejects properly — no vuln here
        if matches!(s1, 400..=403) {
            break;
        }
    }

    vec![]
}
