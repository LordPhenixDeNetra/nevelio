use nevelio_core::types::{Finding, Severity};
use nevelio_core::HttpClient;

use crate::{Endpoint, SimpleEntry, LDAP_ERRORS};

pub(super) async fn check_ldap(
    client: &HttpClient,
    ep: &Endpoint,
    param: &str,
    payloads: &[SimpleEntry],
) -> Vec<Finding> {
    let Some((baseline_status, baseline_len)) = super::get_baseline(client, ep).await else {
        return vec![];
    };

    for entry in payloads {
        let url = super::inject_query(&ep.full_url, param, &entry.value);
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::GET);
        let Ok(req) = client.inner().request(method.clone(), &url).build() else {
            continue;
        };
        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();
        let body_len = body.len();

        let has_ldap_error = LDAP_ERRORS
            .iter()
            .any(|e| body_lower.contains(&e.to_lowercase()));
        let boolean_change = baseline_len > 0
            && (body_len as isize - baseline_len as isize).unsigned_abs() * 100 / baseline_len > 30;
        let status_flip = baseline_status != 200 && status == 200;

        if has_ldap_error || boolean_change || status_flip {
            let proof_detail = if has_ldap_error {
                format!("Erreur LDAP dans la réponse HTTP {}", status)
            } else {
                format!(
                    "Réponse anormale : {} octets vs {} baseline (HTTP {})",
                    body_len, baseline_len, status
                )
            };

            let mut f = Finding::new(
                format!("LDAP Injection — paramètre `{}`", param),
                Severity::High,
                7.5,
                "injection".to_string(),
                ep.full_url.clone(),
                ep.method.clone(),
            );
            f.description = format!(
                "Le paramètre `{}` de l'endpoint {} semble vulnérable à une injection LDAP. \
                 Un attaquant peut manipuler les filtres de recherche LDAP pour contourner \
                 l'authentification ou exfiltrer des informations d'annuaire.",
                param, ep.full_url
            );
            f.proof = format!("Payload: {:?}\n{}", entry.value, proof_detail);
            f.recommendation =
                "Utiliser une API LDAP avec requêtes paramétrées. Encoder les caractères spéciaux \
                 LDAP (*, (, ), \\, \\0). Valider les entrées via une allowlist stricte."
                    .to_string();
            f.cwe = Some("CWE-90".to_string());
            f.references = vec![
                "https://owasp.org/www-community/attacks/LDAP_Injection".to_string(),
                "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html".to_string(),
            ];
            return vec![f];
        }
    }
    vec![]
}
