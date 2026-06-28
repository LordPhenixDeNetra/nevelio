use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::HttpClient;

use super::{send_request, RATE_LIMIT_PROBE_COUNT, USER_AGENTS, XFF_VALUES};

pub(super) async fn check_rate_limit(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let mut successes = 0usize;
    for _ in 0..RATE_LIMIT_PROBE_COUNT {
        if let Some(status) = send_request(client, ep, token, &[], None).await {
            if status != 429 {
                successes += 1;
            }
        }
    }

    if successes == RATE_LIMIT_PROBE_COUNT {
        let mut f = Finding::new(
            "Absence de rate limiting".to_string(),
            Severity::Medium,
            5.3,
            "business-logic".to_string(),
            ep.full_url.clone(),
            ep.method.clone(),
        );
        f.description = format!(
            "L'endpoint {} {} a accepté {} requêtes consécutives sans retourner HTTP 429. \
             L'absence de rate limiting expose l'API aux attaques par brute force, \
             scraping et déni de service applicatif.",
            ep.method, ep.full_url, RATE_LIMIT_PROBE_COUNT
        );
        f.proof = format!(
            "{}/{} requêtes rapides ont reçu un statut ≠ 429",
            successes, RATE_LIMIT_PROBE_COUNT
        );
        f.recommendation =
            "Implémenter un rate limiter par IP et par token (ex: token bucket, sliding window). \
             Retourner HTTP 429 avec un header Retry-After."
                .to_string();
        f.cwe = Some("CWE-770".to_string());
        f.references = vec![
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/".to_string(),
        ];
        return vec![f];
    }

    check_rate_limit_header_bypass(client, ep, token).await
}

pub(super) async fn check_rate_limit_header_bypass(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    for xff in XFF_VALUES {
        let headers = [("X-Forwarded-For", *xff), ("X-Real-IP", *xff)];
        if let Some(status) = send_request(client, ep, token, &headers, None).await {
            if status != 429 {
                let mut f = Finding::new(
                    "Rate Limit Bypass via X-Forwarded-For".to_string(),
                    Severity::Medium,
                    5.8,
                    "business-logic".to_string(),
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le rate limiter de {} est contournable en falsifiant \
                     l'en-tête X-Forwarded-For avec la valeur \"{}\" (HTTP {}).",
                    ep.full_url, xff, status
                );
                f.proof = format!("X-Forwarded-For: {} → HTTP {}", xff, status);
                f.recommendation =
                    "Ne pas se baser sur X-Forwarded-For pour identifier un client car \
                     cet en-tête est forgeable. Utiliser l'IP de connexion réelle ou un \
                     identifiant de session."
                        .to_string();
                f.cwe = Some("CWE-770".to_string());
                f.references = vec![
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/".to_string(),
                ];
                return vec![f];
            }
        }
    }

    for ua in USER_AGENTS {
        let headers = [("User-Agent", *ua)];
        if let Some(status) = send_request(client, ep, token, &headers, None).await {
            if status != 429 {
                let mut f = Finding::new(
                    "Rate Limit Bypass via User-Agent".to_string(),
                    Severity::Low,
                    4.3,
                    "business-logic".to_string(),
                    ep.full_url.clone(),
                    ep.method.clone(),
                );
                f.description = format!(
                    "Le rate limiter de {} semble limiter par User-Agent. \
                     La valeur \"{}\" a obtenu un HTTP {} en contournant la limite.",
                    ep.full_url, ua, status
                );
                f.proof = format!("User-Agent: {} → HTTP {}", ua, status);
                f.recommendation =
                    "Ne pas utiliser le User-Agent comme critère de rate limiting.".to_string();
                f.cwe = Some("CWE-770".to_string());
                f.references = vec![];
                return vec![f];
            }
        }
    }

    vec![]
}
