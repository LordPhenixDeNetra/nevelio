use async_trait::async_trait;
use serde::Deserialize;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Payload file (embedded)
// ---------------------------------------------------------------------------

const IDOR_PAYLOADS: &str = include_str!("../../../../payloads/idor.yaml");

// HTTP methods to probe for BFLA
const ALL_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

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
            findings.extend(check_idor_numeric(client, ep, auth_token).await);

            // IDOR: UUIDs in path
            findings.extend(check_idor_uuid(client, ep, auth_token).await);

            // BFLA: undocumented HTTP methods (deduplicate by path)
            if checked_bfla.insert(ep.path.clone()) {
                findings.extend(check_bfla(client, ep, auth_token).await);
            }

            // Mass Assignment: POST/PUT/PATCH body injection
            if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(
                    check_mass_assignment(client, ep, auth_token, &file.mass_assignment_fields)
                        .await,
                );
            }
        }

        // Vertical privilege escalation: probe admin paths with current token
        if !auth_token.is_empty() {
            findings.extend(
                check_vertical_privesc(client, base_target, auth_token, &file.admin_paths).await,
            );
        }

        findings
    }
}

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
// Check: IDOR — numeric IDs
// ---------------------------------------------------------------------------

async fn check_idor_numeric(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some((prefix, id, suffix)) = extract_numeric_id(&ep.full_url) else {
        return vec![];
    };

    // Baseline
    let Some((baseline_status, baseline_body)) =
        get_with_token(client, &ep.full_url, &ep.method, token).await
    else {
        return vec![];
    };

    if !matches!(baseline_status, 200..=299) {
        return vec![];
    }

    // Deltas from idor.yaml: [1, -1, 2, -2, 10, 100] + common [1,2,3,100,999]
    let mut candidates: Vec<u64> = vec![];
    for delta in &[1i64, -1, 2, -2, 10, 100] {
        let candidate = id as i64 + delta;
        if candidate > 0 && candidate as u64 != id {
            candidates.push(candidate as u64);
        }
    }
    for &common in &[1u64, 2, 3, 100, 999, 1000] {
        if common != id {
            candidates.push(common);
        }
    }
    candidates.dedup();

    for candidate in candidates {
        let url = format!("{}/{}{}", prefix, candidate, suffix);
        let Some((status, body)) = get_with_token(client, &url, &ep.method, token).await else {
            continue;
        };

        if matches!(status, 200..=299) && body != baseline_body {
            let mut f = Finding::new(
                format!("IDOR — ID numérique `{}` → `{}`", id, candidate),
                Severity::High,
                8.1,
                "access-control".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne une ressource différente pour l'ID {} alors que \
                 l'authentification est faite avec le token de l'ID {}. \
                 Un attaquant peut accéder aux données d'autres utilisateurs.",
                ep.full_url, candidate, id
            );
            f.proof = format!(
                "GET {} → HTTP {} ({} octets) ≠ baseline GET {} → HTTP {} ({} octets)",
                url, status, body.len(),
                ep.full_url, baseline_status, baseline_body.len()
            );
            f.recommendation =
                "Vérifier que chaque ressource accédée appartient bien à l'utilisateur \
                 authentifié. Utiliser des identifiants non-prévisibles (UUID v4) et \
                 valider la propriété côté serveur."
                    .to_string();
            f.cwe = Some("CWE-639".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: IDOR — UUID
// ---------------------------------------------------------------------------

async fn check_idor_uuid(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let Some((prefix, original_uuid, suffix)) = extract_uuid(&ep.full_url) else {
        return vec![];
    };

    let Some((baseline_status, _)) =
        get_with_token(client, &ep.full_url, &ep.method, token).await
    else {
        return vec![];
    };

    // Try nil UUID and a freshly generated random UUID
    let candidates = [
        NIL_UUID.to_string(),
        uuid::Uuid::new_v4().to_string(),
    ];

    for candidate in &candidates {
        if candidate == &original_uuid {
            continue;
        }
        let url = format!("{}/{}{}", prefix, candidate, suffix);
        let Some((status, body)) = get_with_token(client, &url, &ep.method, token).await else {
            continue;
        };

        // Suspicious: got 200 when baseline was also 200 with a different UUID,
        // OR got 200 when baseline was 403 (broken access)
        if matches!(status, 200..=299)
            && (baseline_status != 200 || !body.is_empty())
        {
            let mut f = Finding::new(
                format!("IDOR — UUID substitution `{}`", &original_uuid[..8]),
                Severity::High,
                8.1,
                "access-control".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne HTTP {} lorsqu'on substitue l'UUID {} par {}. \
                 Le contrôle d'accès basé sur l'UUID est potentiellement absent.",
                ep.full_url, status, original_uuid, candidate
            );
            f.proof = format!(
                "UUID original: {} | UUID testé: {} → HTTP {}",
                original_uuid, candidate, status
            );
            f.recommendation =
                "Les UUIDs ne sont pas secrets. Vérifier la propriété de la ressource \
                 via le token d'authentification, pas uniquement via l'identifiant."
                    .to_string();
            f.cwe = Some("CWE-639".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: BFLA — Broken Function Level Authorization
// ---------------------------------------------------------------------------

async fn check_bfla(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for method in ALL_METHODS {
        if method.eq_ignore_ascii_case(&ep.method) {
            continue; // skip the documented method
        }

        let Some((status, body)) = get_with_token(client, &ep.full_url, method, token).await else {
            continue;
        };

        if matches!(status, 200..=299) {
            let body_lower = String::from_utf8_lossy(&body).to_lowercase();
            let is_real_error = BFLA_ERROR_INDICATORS
                .iter()
                .any(|kw| body_lower.contains(kw));
            if is_real_error {
                continue;
            }

            let mut f = Finding::new(
                format!("BFLA — méthode {} non documentée acceptée", method),
                Severity::High,
                7.5,
                "access-control".to_string(),
                ep.full_url.clone(),
                method.to_string(),
            );
            f.description = format!(
                "L'endpoint {} n'est documenté que pour {} mais accepte la méthode {} \
                 avec un HTTP {}. Un attaquant peut effectuer des actions non autorisées.",
                ep.full_url, ep.method, method, status
            );
            f.proof = format!(
                "{} {} → HTTP {} (endpoint documenté comme {} uniquement)",
                method, ep.full_url, status, ep.method
            );
            f.recommendation =
                "Configurer une allowlist stricte des méthodes HTTP autorisées sur chaque \
                 endpoint. Retourner 405 Method Not Allowed pour toute méthode non prévue."
                    .to_string();
            f.cwe = Some("CWE-285".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check: Vertical Privilege Escalation (admin paths)
// ---------------------------------------------------------------------------

async fn check_vertical_privesc(
    client: &HttpClient,
    base_target: &str,
    token: &str,
    admin_paths: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = base_target.trim_end_matches('/');

    for path in admin_paths {
        let url = format!("{}{}", base, path);
        let Some((status, _)) = get_with_token(client, &url, "GET", token).await else {
            continue;
        };

        if matches!(status, 200..=299) {
            let mut f = Finding::new(
                format!("Privilege Escalation Verticale — {}", path),
                Severity::Critical,
                9.1,
                "access-control".to_string(),
                url.clone(),
                "GET".to_string(),
            );
            f.description = format!(
                "L'endpoint d'administration {} est accessible avec un token utilisateur standard \
                 (HTTP {}). Un utilisateur non-admin peut accéder à des fonctions privilégiées.",
                url, status
            );
            f.proof = format!("GET {} avec token fourni → HTTP {}", url, status);
            f.recommendation =
                "Implémenter un contrôle de rôle côté serveur sur tous les endpoints admin. \
                 Ne pas se fier uniquement à l'obscurité des URLs."
                    .to_string();
            f.cwe = Some("CWE-269".to_string());
            f.references = vec![
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/".to_string(),
            ];
            findings.push(f);
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Check: Mass Assignment
// ---------------------------------------------------------------------------

async fn check_mass_assignment(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    fields: &[MassField],
) -> Vec<Finding> {
    if fields.is_empty() {
        return vec![];
    }

    // Build a body with all sensitive fields
    let mut body = serde_json::Map::new();
    for f in fields {
        body.insert(f.field.clone(), f.value.clone());
    }
    let body_str = serde_json::Value::Object(body.clone()).to_string();

    let mut req_builder = client
        .inner()
        .request(ep.method.parse().unwrap_or(reqwest::Method::POST), &ep.full_url)
        .header("Content-Type", "application/json")
        .body(body_str.clone());
    if !token.is_empty() {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }

    let req = match req_builder.build() {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    let Ok(resp) = client.send(req).await else {
        return vec![];
    };

    let status = resp.status().as_u16();
    let resp_body = resp.text().await.unwrap_or_default().to_lowercase();

    // Detection: server accepted the request AND reflects one of the injected fields
    let reflected = fields
        .iter()
        .any(|f| resp_body.contains(&f.field.to_lowercase()));

    if matches!(status, 200..=299) && reflected {
        let reflected_fields: Vec<&str> = fields
            .iter()
            .filter(|f| resp_body.contains(&f.field.to_lowercase()))
            .map(|f| f.field.as_str())
            .collect();

        let mut finding = Finding::new(
            "Mass Assignment — champs privilégiés acceptés".to_string(),
            Severity::High,
            8.8,
            "access-control".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        finding.description = format!(
            "L'endpoint {} {} accepte et reflète des champs sensibles non documentés : {}. \
             Un attaquant peut s'octroyer des droits admin ou modifier des attributs protégés.",
            ep.method, ep.full_url,
            reflected_fields.join(", ")
        );
        finding.proof = format!(
            "Body envoyé: {} champs sensibles\nChamps reflétés dans la réponse (HTTP {}): {}",
            fields.len(),
            status,
            reflected_fields.join(", ")
        );
        finding.recommendation =
            "Utiliser une allowlist des champs acceptés (DTO / schema validation). \
             Ne jamais binder directement le body de la requête sur un modèle de données."
                .to_string();
        finding.cwe = Some("CWE-915".to_string());
        finding.references = vec![
            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/".to_string(),
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html".to_string(),
        ];
        return vec![finding];
    }

    vec![]
}
