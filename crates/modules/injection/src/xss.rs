use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, SimpleEntry};

pub(super) async fn check_xss(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let resp = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
            let Ok(req) = client.inner().request(method, &url).build() else {
                continue;
            };
            match client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        } else {
            let body = serde_json::json!({ param: entry.value });
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            else {
                continue;
            };
            match client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        };

        let body = resp.text().await.unwrap_or_default();

        if body.contains(entry.value.as_str()) {
            let mut f = Finding::new(
                format!("XSS réfléchi — paramètre `{}`", param),
                Severity::Medium,
                6.1,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} réfléchit le payload XSS sans encodage. \
                 Un attaquant peut exécuter du JavaScript dans le navigateur de la victime.",
                param, ep.full_url
            );
            f.proof = format!(
                "Payload: {:?} → retrouvé non encodé dans la réponse",
                entry.value
            );
            f.recommendation =
                "Encoder toutes les sorties HTML (htmlspecialchars, DOMPurify). \
                 Ajouter un Content-Security-Policy strict. \
                 Valider les entrées côté serveur."
                    .to_string();
            f.cwe = Some("CWE-79".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/xss/".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}
