use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::send_request;

pub(super) async fn check_price_manipulation(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let price_fields = &["price", "amount", "total", "cost", "subtotal"];
    let manipulated_values: &[(&str, serde_json::Value)] = &[
        ("0",    serde_json::json!(0)),
        ("0.01", serde_json::json!(0.01)),
        ("-1",   serde_json::json!(-1)),
        ("1",    serde_json::json!(1)),
    ];

    let baseline = send_request(client, ep, token, &[], Some("{}")).await;
    let baseline_status = baseline.unwrap_or(0);

    for field in price_fields {
        for (label, value) in manipulated_values {
            let body = serde_json::json!({ (*field): value }).to_string();
            if let Some(status) = send_request(client, ep, token, &[], Some(&body)).await {
                let suspicious = matches!(status, 200..=299)
                    && (!matches!(baseline_status, 200..=299)
                        || value == &serde_json::json!(0)
                        || value == &serde_json::json!(-1));

                if suspicious {
                    let mut f = Finding::new(
                        format!("Price Manipulation — champ `{}` = {}", field, label),
                        Severity::High,
                        8.6,
                        "business-logic".to_string(),
                        ep.full_url.clone(),
                        ep.method.clone(),
                    );
                    f.description = format!(
                        "L'endpoint {} {} accepte un prix de {} pour le champ `{}` (HTTP {}). \
                         Un attaquant peut acheter des biens ou services à un prix arbitraire.",
                        ep.method, ep.full_url, label, field, status
                    );
                    f.proof = format!("Body: {{ \"{}\": {} }} → HTTP {}", field, label, status);
                    f.recommendation =
                        "Le prix doit être calculé et validé exclusivement côté serveur \
                         à partir du catalogue produit. Ne jamais accepter un prix \
                         fourni par le client."
                            .to_string();
                    f.cwe = Some("CWE-20".to_string());
                    f.references = vec![
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/".to_string(),
                    ];
                    return vec![f];
                }
            }
        }
    }

    vec![]
}
