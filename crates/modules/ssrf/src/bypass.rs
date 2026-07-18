use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{urlenc, BYPASS_PROBES};

pub(super) async fn probe_ssrf_bypass(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
) -> Option<Finding> {
    let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

    for bypass in BYPASS_PROBES {
        let result = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
            let sep = if ep.full_url.contains('?') { '&' } else { '?' };
            let url = format!("{}{}{}={}", ep.full_url, sep, param, urlenc(bypass.url));
            let Ok(req) = client.inner().request(method.clone(), &url).build() else {
                continue;
            };
            client.send(req).await.ok()?
        } else {
            let body = serde_json::json!({ param: bypass.url });
            let Ok(req) = client
                .inner()
                .request(method.clone(), &ep.full_url)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .build()
            else {
                continue;
            };
            client.send(req).await.ok()?
        };

        let status = result.status().as_u16();
        let body = result.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();

        let bypass_hit = status == 200
            && (body_lower.contains("localhost")
                || body_lower.contains("127.0.0.1")
                || body_lower.contains("::1")
                || body.len() > 100);

        if bypass_hit {
            let mut f = Finding::new(
                format!("SSRF Bypass — `{}` via {}", param, bypass.description),
                Severity::Critical,
                9.8,
                "ssrf",
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` est vulnérable au SSRF via une technique de bypass : {} (`{}`). \
                 Les filtres basés sur la correspondance de chaînes (\"127.0.0.1\", \"localhost\") \
                 peuvent être contournés par des représentations alternatives.",
                param, bypass.description, bypass.url
            );
            f.proof = format!(
                "Payload: {}={}\nHTTP {} — réponse: {}",
                param,
                bypass.url,
                status,
                body.chars().take(200).collect::<String>()
            );
            f.recommendation =
                "Valider les URLs côté serveur en résolvant le nom d'hôte DNS et en comparant \
                 l'adresse IP résolue contre une liste de plages bloquées (RFC 1918, 169.254.x.x, ::1). \
                 Ne pas se fier à la représentation textuelle de l'URL."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references = vec![
                "https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return Some(f);
        }
    }

    None
}
