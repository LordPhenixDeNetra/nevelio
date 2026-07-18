use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::SSRF_HEADERS;

pub(super) async fn check_header_ssrf(client: &HttpClient, ep: &Endpoint) -> Option<Finding> {
    let header_probes = [
        (
            "http://169.254.169.254/",
            &["ami-id", "instance-id", "local-ipv4", "iam"][..],
        ),
        ("http://localhost/", &["localhost", "127.0.0.1"][..]),
    ];

    for (probe_url, indicators) in &header_probes {
        for header_name in SSRF_HEADERS {
            let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
            let Ok(req) = client
                .inner()
                .request(method, &ep.full_url)
                .header(*header_name, *probe_url)
                .build()
            else {
                continue;
            };

            let Ok(resp) = client.send(req).await else {
                continue;
            };
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();

            let confirmed = indicators.iter().any(|i| body_lower.contains(i));
            let probable =
                !confirmed && status == 200 && body.len() > 50 && body_lower.contains("169.254");

            if confirmed || probable {
                let severity = if confirmed {
                    Severity::Critical
                } else {
                    Severity::High
                };
                let cvss = if confirmed { 9.8 } else { 7.5 };
                let confidence = if confirmed { "Confirmé" } else { "Probable" };

                let mut f = Finding::new(
                    format!("SSRF via header `{}` — {}", header_name, ep.full_url),
                    severity,
                    cvss,
                    "ssrf",
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le header HTTP `{}` est utilisé pour déclencher une requête interne vers `{}`. \
                     Un attaquant peut accéder aux métadonnées cloud ou à des services internes \
                     en injectant des IPs privées dans ce header.",
                    header_name, probe_url
                );
                f.proof = format!(
                    "{} — `{}: {}` → HTTP {} avec indicateurs dans la réponse: {}",
                    confidence,
                    header_name,
                    probe_url,
                    status,
                    body.chars().take(200).collect::<String>()
                );
                f.recommendation =
                    "Ne jamais faire confiance aux headers X-Forwarded-* pour construire des URLs \
                     internes. Valider et normaliser les IPs sources côté infrastructure. \
                     Bloquer les plages d'adresses privées au niveau du pare-feu."
                        .to_string();
                f.cwe = Some("CWE-918".to_string());
                f.references = vec![
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                        .to_string(),
                    "https://portswigger.net/web-security/ssrf".to_string(),
                ];
                return Some(f);
            }
        }
    }

    None
}
