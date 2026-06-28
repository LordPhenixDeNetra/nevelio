use async_trait::async_trait;
use serde::Deserialize;

use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

mod admin;
mod bfla;
mod bola;
mod idor;
mod mass_assignment;
mod method;

// ---------------------------------------------------------------------------
// Payload file (embedded)
// ---------------------------------------------------------------------------

const IDOR_PAYLOADS: &str = include_str!("../../../../payloads/idor.yaml");

// HTTP methods to probe for BFLA / BOLA
const ALL_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

// Method override headers
const METHOD_OVERRIDE_HEADERS: &[(&str, &str)] = &[
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method", "DELETE"),
    ("X-Method-Override", "DELETE"),
];

// Responses that are clearly "method not supported" (not a bypass)
const METHOD_BLOCKED_INDICATORS: &[&str] = &[
    "not allowed", "method not supported", "not implemented", "not permitted",
    "invalid method", "method not found", "unsupported",
];

// UUID nil value
const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

// Body keywords that indicate a real error despite HTTP 2xx (BFLA false-positive filter)
const BFLA_ERROR_INDICATORS: &[&str] = &[
    "not allowed",
    "not implemented",
    "not supported",
    "method not permitted",
    "invalid method",
    "method not found",
    "405",
];

// ---------------------------------------------------------------------------
// Payload structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IdorPayloadFile {
    #[serde(default)]
    admin_paths: Vec<String>,
    #[serde(default)]
    mass_assignment_fields: Vec<MassField>,
}

#[derive(Debug, Deserialize, Clone)]
struct MassField {
    field: String,
    value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct AccessControlModule;

#[async_trait]
impl AttackModule for AccessControlModule {
    fn name(&self) -> &str {
        "access-control"
    }

    fn description(&self) -> &str {
        "Tests IDOR, privilege escalation (horizontal/vertical), BFLA, and mass assignment"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let file: IdorPayloadFile =
            serde_yaml::from_str(IDOR_PAYLOADS).unwrap_or_else(|_| IdorPayloadFile {
                admin_paths: vec![],
                mass_assignment_fields: vec![],
            });

        let auth_token = session.config.auth_token.as_deref().unwrap_or("");
        let base_target = &session.config.target;
        let mut findings = Vec::new();
        let mut checked_bfla = std::collections::HashSet::new();

        for ep in endpoints {
            // IDOR: numeric IDs in path
            findings.extend(idor::check_idor_numeric(client, ep, auth_token).await);

            // IDOR: UUIDs in path
            findings.extend(idor::check_idor_uuid(client, ep, auth_token).await);

            // BFLA: undocumented HTTP methods (deduplicate by path)
            if checked_bfla.insert(ep.path.clone()) {
                findings.extend(bfla::check_bfla(client, ep, auth_token).await);
            }

            // BOLA: cross-resource access across all verbs
            findings.extend(bola::check_bola(client, ep, auth_token).await);

            // HTTP method override bypass
            findings.extend(method::check_method_override(client, ep, auth_token).await);

            // Mass Assignment: POST/PUT/PATCH body injection
            if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(
                    mass_assignment::check_mass_assignment(
                        client,
                        ep,
                        auth_token,
                        &file.mass_assignment_fields,
                    )
                    .await,
                );
            }
        }

        // Vertical privilege escalation: probe admin paths with current token
        if !auth_token.is_empty() {
            findings.extend(
                bfla::check_vertical_privesc(client, base_target, auth_token, &file.admin_paths)
                    .await,
            );
        }

        // Unprotected admin endpoints (no token required)
        findings.extend(
            admin::check_admin_endpoints_unauth(client, base_target, &file.admin_paths).await,
        );

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extracts the first numeric segment from a URL path and returns
/// (prefix_url, numeric_id, suffix_url) so we can rebuild URLs with different IDs.
fn extract_numeric_id(url: &str) -> Option<(String, u64, String)> {
    // Work on path portion only, keeping scheme+host as prefix
    let (base, path) = split_url_path(url)?;
    let segments: Vec<&str> = path.split('/').collect();

    for (i, seg) in segments.iter().enumerate() {
        if let Ok(id) = seg.parse::<u64>() {
            let prefix = format!("{}{}", base, segments[..i].join("/"));
            let suffix = segments[i + 1..].join("/");
            let suffix = if suffix.is_empty() {
                String::new()
            } else {
                format!("/{}", suffix)
            };
            return Some((prefix, id, suffix));
        }
    }
    None
}

/// Returns (scheme+host, /path) split
fn split_url_path(url: &str) -> Option<(String, String)> {
    // Find the third '/' (after "https://host")
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
    let base = url[..scheme_end + 3 + path_start].to_string();
    let path = url[scheme_end + 3 + path_start..].to_string();
    Some((base, path))
}

/// Checks if a URL path segment looks like a UUID (8-4-4-4-12 hex).
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    bytes[8] == b'-' && bytes[13] == b'-' && bytes[18] == b'-' && bytes[23] == b'-'
        && s.chars().enumerate().all(|(i, c)| {
            matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit()
        })
}

fn extract_uuid(url: &str) -> Option<(String, String, String)> {
    let (base, path) = split_url_path(url)?;
    let segments: Vec<&str> = path.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if is_uuid(seg) {
            let prefix = format!("{}{}", base, segments[..i].join("/"));
            let suffix = segments[i + 1..].join("/");
            let suffix = if suffix.is_empty() {
                String::new()
            } else {
                format!("/{}", suffix)
            };
            return Some((prefix, seg.to_string(), suffix));
        }
    }
    None
}

async fn get_with_token(
    client: &HttpClient,
    url: &str,
    method: &str,
    token: &str,
) -> Option<(u16, Vec<u8>)> {
    let mut req = client
        .inner()
        .request(method.parse().unwrap_or(reqwest::Method::GET), url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }
    let req = req.build().ok()?;
    let resp = client.send(req).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.ok()?.to_vec();
    Some((status, body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_numeric_id_finds_id_in_path() {
        let (prefix, id, suffix) =
            extract_numeric_id("https://api.example.com/users/42/profile").unwrap();
        assert_eq!(id, 42);
        assert!(prefix.ends_with("/users"), "prefix: {}", prefix);
        assert_eq!(suffix, "/profile");
    }

    #[test]
    fn extract_numeric_id_root_id() {
        let (_, id, suffix) =
            extract_numeric_id("https://api.example.com/items/123").unwrap();
        assert_eq!(id, 123);
        assert!(suffix.is_empty());
    }

    #[test]
    fn extract_numeric_id_returns_none_without_id() {
        assert!(extract_numeric_id("https://api.example.com/users").is_none());
        assert!(extract_numeric_id("https://api.example.com/").is_none());
    }

    #[test]
    fn is_uuid_valid() {
        assert!(is_uuid("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn is_uuid_invalid() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("123"));
        assert!(!is_uuid("a1b2c3d4-e5f6-7890-abcd-ef123456789")); // too short
        assert!(!is_uuid(""));
    }

    #[test]
    fn extract_uuid_finds_uuid_in_url() {
        let url = "https://api.example.com/resources/a1b2c3d4-e5f6-7890-abcd-ef1234567890/details";
        let (_, uuid, suffix) = extract_uuid(url).unwrap();
        assert_eq!(uuid, "a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert_eq!(suffix, "/details");
    }

    #[test]
    fn extract_uuid_returns_none_without_uuid() {
        assert!(extract_uuid("https://api.example.com/users/123").is_none());
    }

    #[test]
    fn bfla_error_indicator_detects_false_positive() {
        let body = b"HTTP 200 OK: method not allowed for this endpoint";
        let body_lower = String::from_utf8_lossy(body).to_lowercase();
        let is_real_error = BFLA_ERROR_INDICATORS
            .iter()
            .any(|kw| body_lower.contains(kw));
        assert!(is_real_error, "should detect 'not allowed' as error indicator");
    }

    #[test]
    fn bfla_error_indicator_passes_real_success() {
        let body = b"{\"id\":1,\"name\":\"resource\",\"status\":\"active\"}";
        let body_lower = String::from_utf8_lossy(body).to_lowercase();
        let is_real_error = BFLA_ERROR_INDICATORS
            .iter()
            .any(|kw| body_lower.contains(kw));
        assert!(!is_real_error, "clean JSON body should not be flagged");
    }
}
