use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, SstiEntry, SSTI_HEADERS};

pub(super) async fn check_ssti(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SstiEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);

        let req = match client
            .inner()
            .request(ep.method.parse().unwrap_or(reqwest::Method::GET), &url)
            .build()
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let body = resp.text().await.unwrap_or_default();

        if body.contains(&entry.expect) {
            let mut f = Finding::new(
                format!(
                    "Server-Side Template Injection (SSTI) — paramètre `{}`",
                    param
                ),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est évalué par un moteur de templates côté serveur. \
                 L'expression {:?} a produit \"{}\" dans la réponse, indiquant une SSTI exploitable. \
                 Un attaquant peut exécuter du code arbitraire sur le serveur.",
                param, entry.value, entry.expect
            );
            f.proof = format!(
                "Payload: {:?} → résultat attendu {:?} trouvé dans la réponse",
                entry.value, entry.expect
            );
            f.recommendation =
                "Ne jamais rendre des entrées utilisateur directement dans un template. \
                 Utiliser un sandboxing du moteur de templates ou des fonctions d'échappement."
                    .to_string();
            f.cwe = Some("CWE-94".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/server-side-template-injection".to_string(),
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}

pub(super) async fn check_ssti_headers(
    client: &HttpClient,
    ep: &Endpoint,
    payloads: &[SstiEntry],
) -> Vec<Finding> {
    for header_name in SSTI_HEADERS {
        for entry in payloads {
            let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header(*header_name, &entry.value)
                .build()
            else {
                continue;
            };
            let Ok(resp) = client.send(req).await else {
                continue;
            };
            let body = resp.text().await.unwrap_or_default();

            if body.contains(&entry.expect) {
                let mut f = Finding::new(
                    format!("SSTI via header `{}` — {}", header_name, ep.full_url),
                    Severity::Critical,
                    9.8,
                    "injection".to_string(),
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le header HTTP `{}` est évalué par un moteur de templates côté serveur. \
                     L'expression {:?} a produit {:?} dans la réponse. \
                     Un attaquant peut exécuter du code arbitraire sur le serveur.",
                    header_name, entry.value, entry.expect
                );
                f.proof = format!(
                    "Header: {} = {:?} → résultat {:?} trouvé dans la réponse",
                    header_name, entry.value, entry.expect
                );
                f.recommendation =
                    "Ne jamais rendre des headers HTTP dans un contexte de template. \
                     Utiliser un sandboxing du moteur de templates ou des fonctions d'échappement."
                        .to_string();
                f.cwe = Some("CWE-94".to_string());
                f.references = vec![
                    "https://portswigger.net/web-security/server-side-template-injection"
                        .to_string(),
                ];
                return vec![f];
            }
        }
    }
    vec![]
}
