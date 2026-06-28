use std::time::{Duration, Instant};

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{SqliEntry, SQL_ERRORS, TIME_THRESHOLD_MS};

pub(super) async fn check_sqli(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SqliEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = super::get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

        let start = Instant::now();
        let resp = if entry.kind == "time_based" {
            // Extended timeout so the injected delay is measurable
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

        let status = resp.status().as_u16();
        let body_bytes = resp.bytes().await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes).to_lowercase();
        let body_len = body_bytes.len();

        let triggered = match entry.kind.as_str() {
            "time_based" => elapsed >= TIME_THRESHOLD_MS,
            "error" => SQL_ERRORS.iter().any(|e| body.contains(e)) || status == 500,
            "boolean" | "bypass" => {
                // Significant change in response (body length ±20% or status flip)
                let ratio = if baseline_len == 0 {
                    body_len > 0
                } else {
                    let diff = (body_len as isize - baseline_len as isize).unsigned_abs();
                    diff * 100 / baseline_len > 20
                };
                ratio || (baseline_status != 200 && status == 200)
            }
            "union" => body_len > baseline_len + 50,
            _ => false,
        };

        if triggered {
            let proof = match entry.kind.as_str() {
                "time_based" => format!(
                    "Délai de réponse : {}ms (seuil {}ms)",
                    elapsed, TIME_THRESHOLD_MS
                ),
                "error" => format!("Erreur SQL dans la réponse (HTTP {})", status),
                _ => format!(
                    "Réponse anormale : {} octets vs {} baseline (HTTP {})",
                    body_len, baseline_len, status
                ),
            };

            let mut f = Finding::new(
                format!("SQL Injection ({}) — paramètre `{}`", entry.kind, param),
                Severity::Critical,
                9.8,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} semble vulnérable à une injection SQL de type {}. \
                 Un attaquant peut lire, modifier ou supprimer des données de la base.",
                param, ep.full_url, entry.kind
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof);
            f.recommendation =
                "Utiliser des requêtes préparées (parameterized queries) et un ORM sécurisé. \
                 Ne jamais concaténer des entrées utilisateur dans des requêtes SQL."
                    .to_string();
            f.cwe = Some("CWE-89".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f]; // one finding per param per endpoint is sufficient
        }
    }

    vec![]
}
