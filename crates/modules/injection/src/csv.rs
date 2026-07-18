use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, SimpleEntry};

pub(super) fn is_export_endpoint(ep: &Endpoint) -> bool {
    let path = ep.path.to_lowercase();
    let url = ep.full_url.to_lowercase();
    ["export", "download", "csv", "report", "xls", "xlsx"]
        .iter()
        .any(|kw| path.contains(kw) || url.contains(kw))
}

pub(super) async fn check_csv_injection(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
        let Ok(req) = client.inner().request(method, &url).build() else {
            continue;
        };
        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        // Unescaped formula in CSV response is the indicator
        if matches!(status, 200..=299) && body.contains(entry.value.as_str()) {
            let mut f = Finding::new(
                format!("CSV/Formula Injection — paramètre `{}`", param),
                Severity::Medium,
                5.0,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "L'endpoint {} retourne une formule non échappée dans un export CSV/Excel. \
                 Un attaquant peut injecter des formules malveillantes qui s'exécutent \
                 lorsqu'un utilisateur ouvre le fichier dans un tableur.",
                ep.full_url
            );
            f.proof = format!(
                "Payload: {:?} → retrouvé non échappé dans la réponse CSV (HTTP {})",
                entry.value, status
            );
            f.recommendation =
                "Préfixer les valeurs commençant par =, +, -, @ avec un apostrophe dans les exports CSV. \
                 Utiliser une bibliothèque de génération CSV qui gère automatiquement l'échappement."
                    .to_string();
            f.cwe = Some("CWE-1236".to_string());
            f.references =
                vec!["https://owasp.org/www-community/attacks/CSV_Injection".to_string()];
            return vec![f];
        }
    }
    vec![]
}
