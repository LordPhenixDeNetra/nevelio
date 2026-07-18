use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, NosqliEntry};

pub(super) async fn check_nosqli(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[NosqliEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = super::get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        // Send as JSON body for POST/PUT; bracket notation for GET/DELETE
        let resp = if ep.method == "GET" || ep.method == "DELETE" {
            let url = super::inject_nosql_query(&ep.full_url, param, &entry.value);
            let req = match client
                .inner()
                .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &url)
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            client.send(req).await
        } else {
            let body = serde_json::json!({
                param: serde_json::from_str::<serde_json::Value>(&entry.value)
                    .unwrap_or(serde_json::Value::String(entry.value.clone()))
            });
            let req = match client
                .inner()
                .request(
                    ep.method.parse().unwrap_or(reqwest::Method::POST),
                    &ep.full_url,
                )
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            client.send(req).await
        };

        let Ok(resp) = resp else { continue };

        let status = resp.status().as_u16();
        let body_len = resp.bytes().await.unwrap_or_default().len();

        let triggered = (baseline_status != 200 && status == 200)
            || (baseline_len > 0
                && (body_len as isize - baseline_len as isize).unsigned_abs() * 100 / baseline_len
                    > 30);

        if triggered {
            let mut f = Finding::new(
                format!("NoSQL Injection — paramètre `{}`", param),
                Severity::Critical,
                9.0,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` semble vulnérable à une injection NoSQL (opérateur MongoDB). \
                 Un attaquant peut contourner l'authentification ou lire des données arbitraires.",
                param
            );
            f.proof = format!(
                "Payload: {:?}\nRéponse : HTTP {} ({} octets) vs baseline HTTP {} ({} octets)",
                entry.value, status, body_len, baseline_status, baseline_len
            );
            f.recommendation =
                "Valider et typer strictement les entrées. Ne jamais passer d'objets non validés \
                 à des requêtes MongoDB. Utiliser un schema de validation (Joi, Zod, etc.)."
                    .to_string();
            f.cwe = Some("CWE-943".to_string());
            f.references = vec![
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}
