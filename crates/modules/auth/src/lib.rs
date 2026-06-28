use async_trait::async_trait;
use serde::Deserialize;

use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

mod basic;
mod jwt_advanced;
mod jwt_checks;
mod jwt_helpers;
mod refresh;
mod unprotected;

// ---------------------------------------------------------------------------
// Payload definitions (embedded from payloads/jwt.yaml)
// ---------------------------------------------------------------------------

const JWT_PAYLOADS: &str = include_str!("../../../../payloads/jwt.yaml");

const COMMON_BASIC_CREDS: &[(&str, &str)] = &[
    // Default/factory credentials
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", "letmein"),
    ("admin", "qwerty"),
    ("admin", "welcome"),
    ("admin", ""),
    // Root variants
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("root", ""),
    // Common service accounts
    ("test", "test"),
    ("test", "test123"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("operator", "operator"),
    ("support", "support"),
    ("demo", "demo"),
    ("demo", "password"),
    // Application-specific defaults
    ("api", "api"),
    ("service", "service"),
    ("superuser", "superuser"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("sa", ""),
    ("sa", "sa"),
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
            if jwt_helpers::is_jwt(stripped) {
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
                jwt_advanced::check_jwt_algo_confusion(client, base_target, token, &jwks_paths)
                    .await,
            );
        }

        // Refresh token replay (once per target, not per endpoint)
        findings.extend(refresh::check_refresh_token_replay(client, base_target).await);

        for ep in endpoints {
            // --- 1. Missing Authentication ---
            findings.extend(unprotected::check_unprotected_endpoint(client, ep, &auth_token).await);

            // --- 2. JWT + Basic Auth (once per unique URL to avoid flooding) ---
            if checked_bases.insert(ep.full_url.clone()) {
                if let Some(ref token) = jwt_token {
                    findings.extend(jwt_checks::check_jwt_alg_none(client, ep, token).await);
                    findings.extend(jwt_checks::check_jwt_expired(client, ep, token).await);
                    findings.extend(
                        jwt_advanced::check_jwt_kid_injection(client, ep, token, &kid_payloads)
                            .await,
                    );
                    findings.extend(jwt_advanced::check_jwt_jku_ssrf(client, ep, token).await);

                    let found_secret = jwt_checks::check_jwt_weak_secret(
                        client,
                        ep,
                        token,
                        &weak_secrets,
                        &mut findings,
                    )
                    .await;

                    if let Some(secret) = found_secret {
                        findings.extend(
                            jwt_checks::check_jwt_claims(
                                client,
                                ep,
                                token,
                                &secret,
                                &claims_to_test,
                            )
                            .await,
                        );
                    }
                }

                findings.extend(basic::check_basic_auth(client, ep).await);
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
        assert!(jwt_helpers::is_jwt(token));
    }

    #[test]
    fn is_jwt_rejects_non_jwt() {
        assert!(!jwt_helpers::is_jwt("Bearer abc123"));
        assert!(!jwt_helpers::is_jwt("not-a-token"));
        assert!(!jwt_helpers::is_jwt(""));
        assert!(!jwt_helpers::is_jwt("only.two"));
    }

    #[test]
    fn forge_alg_none_produces_three_parts() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0In0\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let forged = jwt_helpers::forge_alg_none(token).expect("should produce a token");
        let parts: Vec<&str> = forged.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");
        assert!(
            forged.ends_with('.'),
            "alg:none token must end with empty signature"
        );
    }

    #[test]
    fn forge_alg_none_preserves_payload() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                     .eyJzdWIiOiIxMjM0In0\
                     .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let forged = jwt_helpers::forge_alg_none(token).unwrap();
        let parts: Vec<&str> = forged.split('.').collect();
        let original_parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts[1], original_parts[1], "payload must be unchanged");
    }

    #[test]
    fn forge_alg_none_rejects_invalid_token() {
        assert!(jwt_helpers::forge_alg_none("not.valid").is_none());
        assert!(jwt_helpers::forge_alg_none("").is_none());
    }
}
