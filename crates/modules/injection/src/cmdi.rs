use std::time::{Duration, Instant};

use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{CmdiEntry, Endpoint, TIME_THRESHOLD_MS};

pub(super) async fn check_cmdi(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[CmdiEntry],
) -> Vec<Finding> {
    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);
        let is_time = entry.detect == "delay_gt_4000ms";
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let start = Instant::now();
        let resp = if is_time {
            // Extended timeout so the injected sleep is measurable
            let Ok(req) = client
                .inner()
                .request(method, &url)
                .timeout(Duration::from_millis(TIME_THRESHOLD_MS as u64 + 3_000))
                .build()
            else {
                continue;
            };
            match client.inner().execute(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        } else {
            let Ok(req) = client.inner().request(method, &url).build() else {
                continue;
            };
            match client.send(req).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        };
        let elapsed = start.elapsed().as_millis();

        let triggered = if is_time {
            elapsed >= TIME_THRESHOLD_MS
        } else {
            let body = resp.text().await.unwrap_or_default();
            body.contains(&entry.detect)
        };

        if triggered {
            let proof = if is_time {
                format!(
                    "Délai de réponse : {}ms (seuil {}ms)",
                    elapsed, TIME_THRESHOLD_MS
                )
            } else {
                format!("Sortie système détectée : {:?}", entry.detect)
            };

            let mut f = Finding::new(
                format!("Command Injection — paramètre `{}`", param),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est passé sans assainissement à un interpréteur de commandes système. \
                 Un attaquant peut exécuter des commandes arbitraires sur le serveur.",
                param
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof);
            f.recommendation =
                "Ne jamais construire des commandes shell à partir d'entrées utilisateur. \
                 Utiliser des API système directes (exec avec args séparés) et valider strictement \
                 les entrées via une allowlist."
                    .to_string();
            f.cwe = Some("CWE-77".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/Command_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }

    vec![]
}
