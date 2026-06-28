use async_trait::async_trait;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// OAuth2 endpoint patterns
// ---------------------------------------------------------------------------

const AUTHORIZE_PATHS: &[&str] = &[
    "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
    "/connect/authorize", "/authorize", "/oauth/auth",
    "/login/oauth/authorize", "/api/oauth/authorize",
    "/v1/oauth/authorize", "/v2/oauth/authorize",
];

const TOKEN_PATHS: &[&str] = &[
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/connect/token", "/token", "/api/token",
    "/v1/oauth/token", "/v2/oauth/token",
];

const INTROSPECT_PATHS: &[&str] = &[
    "/oauth/introspect", "/oauth2/introspect", "/introspect",
    "/connect/introspect", "/token/introspect", "/auth/introspect",
];

pub const REVOKE_PATHS: &[&str] = &[
    "/oauth/revoke", "/oauth2/revoke", "/revoke", "/token/revoke",
];

const JWKS_PATHS: &[&str] = &[
    "/.well-known/jwks.json", "/oauth/jwks", "/.well-known/openid-configuration",
];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct OAuth2Module;

#[async_trait]
impl AttackModule for OAuth2Module {
    fn name(&self) -> &str {
        "oauth2"
    }

    fn description(&self) -> &str {
        "Teste les flows OAuth2/OIDC : redirect_uri manipulation, state absent, PKCE bypass, introspection non protégée"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base = &session.config.target;

        // ── Discovery: look for OAuth2 endpoints in the spec first ──────────
        let auth_endpoints = collect_matching(endpoints, AUTHORIZE_PATHS);
        let token_endpoints = collect_matching(endpoints, TOKEN_PATHS);
        let introspect_endpoints = collect_matching(endpoints, INTROSPECT_PATHS);

        // ── Also probe well-known paths not in spec ──────────────────────────
        findings.extend(probe_redirect_uri(client, base, &auth_endpoints).await);
        findings.extend(probe_missing_state(client, base, &auth_endpoints).await);
        findings.extend(probe_pkce_bypass(client, base, &auth_endpoints).await);
        findings.extend(probe_introspect_unauth(client, base, &introspect_endpoints).await);
        findings.extend(probe_token_endpoint_methods(client, base, &token_endpoints).await);
        findings.extend(probe_open_jwks(client, base).await);
        findings.extend(probe_implicit_flow(client, base, &auth_endpoints).await);
        findings.extend(probe_code_replay(client, base, &token_endpoints).await);
        findings.extend(probe_client_enumeration(client, base, &auth_endpoints).await);

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_matching<'a>(endpoints: &'a [Endpoint], patterns: &[&str]) -> Vec<&'a Endpoint> {
    endpoints
        .iter()
        .filter(|ep| {
            patterns
                .iter()
                .any(|p| ep.path.to_lowercase().contains(p) || ep.full_url.to_lowercase().contains(p))
        })
        .collect()
}

/// Build a URL by replacing the path in the base target
fn build_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{}{}", base, path)
}

async fn get_text(client: &HttpClient, url: &str) -> Option<(u16, String)> {
    let req = client.inner().get(url).build().ok()?;
    let resp = client.send(req).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some((status, body))
}

// ---------------------------------------------------------------------------
// Check 1: redirect_uri manipulation
// ---------------------------------------------------------------------------

async fn probe_redirect_uri(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build the list of endpoints to test (spec + well-known paths)
    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        AUTHORIZE_PATHS.iter().map(|p| build_url(base, p)).collect()
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
                urlenc(redir)
            );
            let Some((status, body)) = get_text(client, &test_url).await else {
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

async fn probe_missing_state(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        AUTHORIZE_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        // Request without state parameter
        let test_url = format!(
            "{}?response_type=code&client_id=test&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&scope=openid",
            url
        );
        let Some((status, body)) = get_text(client, &test_url).await else {
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

async fn probe_pkce_bypass(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        AUTHORIZE_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        // Requête qui devrait exiger PKCE mais ne fournit pas code_challenge
        let test_url = format!(
            "{}?response_type=code&client_id=public-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid&state=random123",
            url
        );
        let Some((status, body)) = get_text(client, &test_url).await else {
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

// ---------------------------------------------------------------------------
// Check 4: Token introspection non protégée
// ---------------------------------------------------------------------------

async fn probe_introspect_unauth(
    client: &HttpClient,
    base: &str,
    introspect_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = introspect_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        INTROSPECT_PATHS.iter().map(|p| build_url(base, p)).collect()
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
            && (body_lower.contains("\"active\"") || body_lower.contains("\"sub\"") || body_lower.contains("\"scope\""));

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

async fn probe_token_endpoint_methods(
    client: &HttpClient,
    base: &str,
    token_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = token_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        TOKEN_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        let test_url = format!(
            "{}?grant_type=authorization_code&code=test&redirect_uri=https%3A%2F%2Fexample.com",
            url
        );
        let Some((status, _body)) = get_text(client, &test_url).await else {
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

async fn probe_open_jwks(client: &HttpClient, base: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in JWKS_PATHS {
        let url = build_url(base, path);
        let Some((status, body)) = get_text(client, &url).await else {
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

// ---------------------------------------------------------------------------
// URL encoding helper
// ---------------------------------------------------------------------------

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Check 7: Implicit flow (response_type=token)
// ---------------------------------------------------------------------------

async fn probe_implicit_flow(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        AUTHORIZE_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    for url in &probe_urls {
        let test_url = format!(
            "{}?response_type=token&client_id=nevelio_test&redirect_uri={}&scope=openid",
            url,
            urlenc("https://nevelio.example.com/callback")
        );
        let Some((status, body)) = get_text(client, &test_url).await else { continue };

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

async fn probe_code_replay(
    client: &HttpClient,
    base: &str,
    token_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = token_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        TOKEN_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    let replay_code = "nevelio_replay_code_test_12345";
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id=nevelio_test",
        replay_code,
        urlenc("https://nevelio.example.com/callback")
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
            || *s2 == 400 || *s2 == 401;

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

// ---------------------------------------------------------------------------
// Check 9: Client ID enumeration
// ---------------------------------------------------------------------------

const COMMON_CLIENT_IDS: &[&str] = &[
    "app", "client", "mobile", "web", "spa", "api", "default",
    "test", "admin", "demo", "dev", "prod", "frontend", "backend",
    "android", "ios", "native", "public", "internal",
];

async fn probe_client_enumeration(
    client: &HttpClient,
    base: &str,
    auth_endpoints: &[&Endpoint],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let spec_urls: Vec<String> = auth_endpoints.iter().map(|e| e.full_url.clone()).collect();
    let probe_urls: Vec<String> = if spec_urls.is_empty() {
        AUTHORIZE_PATHS.iter().map(|p| build_url(base, p)).collect()
    } else {
        spec_urls
    };

    // Baseline: try an obviously invalid client_id and note the response
    let invalid_url = format!(
        "{}?response_type=code&client_id=nevelio_definitely_invalid_xxxx&redirect_uri={}",
        probe_urls.first().unwrap_or(&build_url(base, AUTHORIZE_PATHS[0])),
        urlenc("https://nevelio.example.com/callback")
    );
    let baseline = get_text(client, &invalid_url).await;
    let baseline_status = baseline.as_ref().map(|(s, _)| *s).unwrap_or(404);

    let mut found_clients: Vec<String> = Vec::new();

    for url in &probe_urls {
        for client_id in COMMON_CLIENT_IDS {
            let test_url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}",
                url,
                client_id,
                urlenc("https://nevelio.example.com/callback")
            );
            let Some((status, body)) = get_text(client, &test_url).await else { continue };
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
