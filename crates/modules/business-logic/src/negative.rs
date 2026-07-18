use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{send_request, NUMERIC_FIELD_NAMES};

pub(super) async fn check_negative_values(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let test_values: &[(&str, serde_json::Value)] = &[
        ("-1", serde_json::json!(-1)),
        ("-0.01", serde_json::json!(-0.01)),
        ("0", serde_json::json!(0)),
        ("2147483647", serde_json::json!(2147483647i64)),
        ("-2147483648", serde_json::json!(-2147483648i64)),
        ("9999999999", serde_json::json!(9999999999i64)),
    ];

    for field in NUMERIC_FIELD_NAMES {
        for (label, value) in test_values {
            let body = serde_json::json!({ (*field): value }).to_string();
            if let Some(status) = send_request(client, ep, token, &[], Some(&body)).await {
                if matches!(status, 200..=299) {
                    let mut f = Finding::new(
                        format!("Valeur invalide acceptée — champ `{}` = {}", field, label),
                        Severity::Medium,
                        6.5,
                        "business-logic".to_string(),
                        ep.full_url.clone(),
                        ep.method.clone(),
                    );
                    f.description = format!(
                        "L'endpoint {} {} a accepté la valeur {} pour le champ `{}` (HTTP {}). \
                         Des montants négatifs ou nuls peuvent entraîner des enrichissements \
                         injustifiés (crédits négatifs, remboursements frauduleux).",
                        ep.method, ep.full_url, label, field, status
                    );
                    f.proof = format!("Body: {{ \"{}\": {} }} → HTTP {}", field, label, status);
                    f.recommendation = format!(
                        "Valider que le champ `{}` est strictement positif côté serveur. \
                         Ne pas se fier uniquement à la validation côté client.",
                        field
                    );
                    f.cwe = Some("CWE-20".to_string());
                    f.references = vec![
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/".to_string(),
                    ];
                    return vec![f];
                }
            }
        }
    }

    vec![]
}
