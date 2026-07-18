use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{urlenc, PROBES};

pub(super) struct ProbeResult {
    pub status: u16,
    pub body: String,
}

pub(super) async fn probe_ssrf(client: &HttpClient, ep: &Endpoint, param: &str) -> Option<Finding> {
    for probe in PROBES {
        let result = send_ssrf_request(client, ep, param, probe.url).await?;

        let body_lower = result.body.to_lowercase();
        let probe_url_lower = probe.url.to_lowercase();

        let confirmed = probe
            .indicators
            .iter()
            .any(|i| body_lower.contains(&i.to_lowercase()));
        let probable = !confirmed
            && result.status == 200
            && !result.body.is_empty()
            && result.body.len() > 50
            && (body_lower.contains("169.254") || body_lower.contains(&probe_url_lower));

        if confirmed || probable {
            let severity = if confirmed {
                Severity::Critical
            } else {
                Severity::High
            };
            let cvss = if confirmed { 9.8 } else { 7.5 };

            let mut f = Finding::new(
                format!("SSRF — paramètre `{}` → {}", param, probe.description),
                severity,
                cvss,
                "ssrf",
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} a été utilisé pour déclencher une requête \
                 vers `{}` ({}). Un attaquant peut accéder à des métadonnées cloud, des services \
                 internes ou des ressources protégées.",
                param, ep.full_url, probe.url, probe.description
            );
            f.proof = format!(
                "Paramètre injecté: {}={}\nRéponse HTTP {}: {}",
                param,
                probe.url,
                result.status,
                result.body.chars().take(300).collect::<String>()
            );
            f.recommendation =
                "Valider strictement les URLs fournies par l'utilisateur via une allowlist de domaines \
                 autorisés. Bloquer les plages d'adresses privées (10.x, 172.16.x, 192.168.x, 169.254.x) \
                 au niveau réseau. Utiliser IMDSv2 (AWS) avec en-tête de session requis. \
                 Ne jamais exposer directement les paramètres d'URL à des clients non authentifiés."
                    .to_string();
            f.cwe = Some("CWE-918".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
                "https://portswigger.net/web-security/ssrf".to_string(),
            ];
            return Some(f);
        }
    }

    None
}

pub(super) async fn send_ssrf_request(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    probe_url: &str,
) -> Option<ProbeResult> {
    let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);

    let resp = if matches!(ep.method.as_str(), "GET" | "HEAD" | "DELETE") {
        let sep = if ep.full_url.contains('?') { '&' } else { '?' };
        let url = format!("{}{}{}={}", ep.full_url, sep, param, urlenc(probe_url));
        let req = client.inner().request(method, &url).build().ok()?;
        client.send(req).await.ok()?
    } else {
        let body = serde_json::json!({ param: probe_url });
        let req = client
            .inner()
            .request(method, &ep.full_url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .build()
            .ok()?;
        client.send(req).await.ok()?
    };

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some(ProbeResult { status, body })
}
