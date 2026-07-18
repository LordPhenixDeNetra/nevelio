use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::MassField;

// ---------------------------------------------------------------------------
// Check: Mass Assignment
// ---------------------------------------------------------------------------

pub(super) async fn check_mass_assignment(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    fields: &[MassField],
) -> Vec<Finding> {
    // Build body from hardcoded sensitive fields + any body/query parameters from the OpenAPI spec
    // that are NOT in the documented parameter list (i.e., extra fields the spec doesn't accept).
    let mut body = serde_json::Map::new();

    // 1. Hardcoded sensitive fields (isAdmin, role, permissions, etc.)
    for f in fields {
        body.insert(f.field.clone(), f.value.clone());
    }

    // 2. Spec parameters augmented with privilege-escalation values
    // We inject each spec field with a value that could trigger privilege escalation.
    let spec_param_names: Vec<String> = ep
        .parameters
        .iter()
        .filter(|p| {
            matches!(
                p.location,
                nevelio_core::types::ParameterLocation::Body
                    | nevelio_core::types::ParameterLocation::Query
            )
        })
        .map(|p| p.name.clone())
        .collect();

    for param in &spec_param_names {
        let param_lower = param.to_lowercase();
        // Only inject spec params that look privilege-sensitive and aren't already in the body
        let is_priv_sensitive = [
            "role",
            "permission",
            "admin",
            "level",
            "group",
            "verified",
            "premium",
            "scope",
            "grant",
            "access",
        ]
        .iter()
        .any(|kw| param_lower.contains(kw));
        if is_priv_sensitive && !body.contains_key(param) {
            body.insert(param.clone(), serde_json::json!("admin"));
        }
    }

    if body.is_empty() {
        return vec![];
    }

    let body_str = serde_json::Value::Object(body.clone()).to_string();

    let mut req_builder = client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::POST),
            &ep.full_url,
        )
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
    let all_injected_keys: Vec<String> = body.keys().cloned().collect();
    let reflected_keys: Vec<String> = all_injected_keys
        .iter()
        .filter(|k| resp_body.contains(&k.to_lowercase()))
        .cloned()
        .collect();

    if matches!(status, 200..=299) && !reflected_keys.is_empty() {
        let source = if reflected_keys
            .iter()
            .any(|k| fields.iter().any(|f| f.field == *k))
        {
            "champs privilégiés hardcodés"
        } else {
            "champs de la spec OpenAPI"
        };

        let mut finding = Finding::new(
            "Mass Assignment — champs privilégiés acceptés".to_string(),
            Severity::High,
            8.8,
            "access-control".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        finding.description = format!(
            "L'endpoint {} {} accepte et reflète des champs sensibles ({}) : {}. \
             Un attaquant peut s'octroyer des droits admin ou modifier des attributs protégés.",
            ep.method,
            ep.full_url,
            source,
            reflected_keys.join(", ")
        );
        finding.proof = format!(
            "Body envoyé: {} champs\nChamps reflétés dans la réponse (HTTP {}): {}",
            all_injected_keys.len(),
            status,
            reflected_keys.join(", ")
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
