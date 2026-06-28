use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::ClaimTest;

// ---------------------------------------------------------------------------
// Check: JWT alg:none bypass
// ---------------------------------------------------------------------------

pub(super) async fn check_jwt_alg_none(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some(none_token) = super::jwt_helpers::forge_alg_none(token) else {
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

pub(super) async fn check_jwt_weak_secret(
    _client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    secrets: &[String],
    findings: &mut Vec<Finding>,
) -> Option<String> {
    for secret in secrets {
        let mut val = Validation::new(Algorithm::HS256);
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

pub(super) async fn check_jwt_claims(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    secret: &str,
    claims_to_test: &[ClaimTest],
) -> Vec<Finding> {
    let Some(base_claims) = super::jwt_helpers::decode_jwt_claims(token) else {
        return vec![];
    };

    let mut findings = Vec::new();

    for claim_test in claims_to_test {
        for value in &claim_test.values {
            let mut modified = base_claims.clone();
            if let Some(obj) = modified.as_object_mut() {
                obj.insert(claim_test.field.clone(), value.clone());
            }

            let Some(forged) = super::jwt_helpers::forge_signed_token(&modified, secret) else {
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

pub(super) async fn check_jwt_expired(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some(expired_token) = super::jwt_helpers::forge_expired_token(token) else {
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
            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                .to_string(),
        ];
        return vec![f];
    }

    vec![]
}
