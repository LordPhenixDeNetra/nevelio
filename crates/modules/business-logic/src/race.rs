use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{is_mutation_endpoint, RACE_PROBE_COUNT};

pub(super) async fn check_race_condition(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    if !is_mutation_endpoint(ep) {
        return vec![];
    }

    let mut handles = Vec::with_capacity(RACE_PROBE_COUNT);
    for _ in 0..RACE_PROBE_COUNT {
        let method = ep.method.parse().unwrap_or(reqwest::Method::POST);
        let url = ep.full_url.clone();
        let auth = if token.is_empty() { None } else { Some(format!("Bearer {}", token)) };
        let inner = client.inner().clone();

        handles.push(tokio::spawn(async move {
            let mut builder = inner.request(method, &url);
            if let Some(ref h) = auth { builder = builder.header("Authorization", h); }
            builder = builder.header("Content-Type", "application/json").body("{}");
            let req = builder.build().ok()?;
            let resp = inner.execute(req).await.ok()?;
            Some(resp.status().as_u16())
        }));
    }

    let mut success_count = 0usize;
    for handle in handles {
        if let Ok(Some(status)) = handle.await {
            if matches!(status, 200..=299) { success_count += 1; }
        }
    }

    if success_count > RACE_PROBE_COUNT / 2 {
        let mut f = Finding::new(
            "Race Condition potentielle".to_string(),
            Severity::High,
            7.5,
            "business-logic".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description = format!(
            "{} sur {} requêtes parallèles identiques vers {} ont retourné un succès. \
             Une race condition peut permettre d'exécuter une action une seule fois \
             (paiement, coupon, retrait) plusieurs fois simultanément.",
            success_count, RACE_PROBE_COUNT, ep.full_url
        );
        f.proof = format!("{}/{} requêtes simultanées → HTTP 2xx", success_count, RACE_PROBE_COUNT);
        f.recommendation =
            "Utiliser des verrous optimistes (version field, ETag) ou des transactions \
             atomiques côté base de données. Implémenter une idempotence par clé de \
             demande (Idempotency-Key header)."
                .to_string();
        f.cwe = Some("CWE-362".to_string());
        f.references = vec![
            "https://portswigger.net/web-security/race-conditions".to_string(),
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/".to_string(),
        ];
        return vec![f];
    }

    vec![]
}
