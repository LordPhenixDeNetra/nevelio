use async_trait::async_trait;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of rapid requests to probe for rate limiting.
const RATE_LIMIT_PROBE_COUNT: usize = 20;

/// Number of parallel requests to probe for race conditions.
const RACE_PROBE_COUNT: usize = 10;

/// Keywords that identify financial / transactional endpoints.
const FINANCIAL_KEYWORDS: &[&str] = &[
    "order", "payment", "checkout", "purchase", "cart", "buy",
    "coupon", "promo", "discount", "voucher", "redeem",
    "transfer", "withdraw", "deposit", "refund", "invoice",
    "subscription", "charge", "billing",
];

/// Numeric field names likely to represent money / quantities.
const NUMERIC_FIELD_NAMES: &[&str] = &[
    "price", "amount", "quantity", "qty", "total", "cost",
    "fee", "discount", "coupon_value", "points", "credits",
    "balance", "subtotal", "tax", "tip",
];

/// X-Forwarded-For values for rate-limit bypass probing.
const XFF_VALUES: &[&str] = &[
    "127.0.0.1", "10.0.0.1", "192.168.1.1",
    "172.16.0.1", "1.1.1.1", "8.8.8.8",
];

/// User-Agent strings for rate-limit bypass probing.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "PostmanRuntime/7.32.1",
    "Go-http-client/1.1",
];

#[cfg(test)]
mod tests {
    use super::*;
    use nevelio_core::types::Endpoint;

    fn ep(path: &str, method: &str) -> Endpoint {
        Endpoint {
            method: method.to_string(),
            path: path.to_string(),
            full_url: format!("https://api.example.com{}", path),
            parameters: vec![],
            auth_required: false,
        }
    }

    #[test]
    fn is_mutation_endpoint_detects_financial_keywords() {
        assert!(is_mutation_endpoint(&ep("/api/payment/confirm", "POST")));
        assert!(is_mutation_endpoint(&ep("/checkout/submit", "POST")));
        assert!(is_mutation_endpoint(&ep("/cart/buy", "POST")));
        assert!(is_mutation_endpoint(&ep("/coupon/redeem", "POST")));
    }

    #[test]
    fn is_mutation_endpoint_ignores_non_financial() {
        assert!(!is_mutation_endpoint(&ep("/users/profile", "GET")));
        assert!(!is_mutation_endpoint(&ep("/docs/openapi.json", "GET")));
    }

    #[test]
    fn financial_keywords_cover_common_patterns() {
        let keywords = FINANCIAL_KEYWORDS;
        assert!(keywords.contains(&"payment"));
        assert!(keywords.contains(&"checkout"));
        assert!(keywords.contains(&"refund"));
        assert!(keywords.contains(&"coupon"));
    }

    #[test]
    fn numeric_field_names_cover_price_fields() {
        assert!(NUMERIC_FIELD_NAMES.contains(&"price"));
        assert!(NUMERIC_FIELD_NAMES.contains(&"amount"));
        assert!(NUMERIC_FIELD_NAMES.contains(&"quantity"));
    }

    #[test]
    fn rate_limit_probe_count_reasonable() {
        assert!(RATE_LIMIT_PROBE_COUNT >= 10);
        assert!(RACE_PROBE_COUNT >= 5);
    }
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct BusinessLogicModule;

#[async_trait]
impl AttackModule for BusinessLogicModule {
    fn name(&self) -> &str {
        "business-logic"
    }

    fn description(&self) -> &str {
        "Tests rate limit bypass, race conditions, negative values, and workflow bypass"
    }

    async fn run(
        &self,
        session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let token = session.config.auth_token.as_deref().unwrap_or("");
        let mut findings = Vec::new();

        for ep in endpoints {
            let is_financial = FINANCIAL_KEYWORDS
                .iter()
                .any(|kw| ep.full_url.to_lowercase().contains(kw));

            // Rate limit bypass (all endpoints)
            findings.extend(check_rate_limit(client, ep, token).await);

            // Race condition (POST/PUT on financial endpoints)
            if is_financial && matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(check_race_condition(client, ep, token).await);
            }

            // Negative / boundary values (POST/PUT/PATCH)
            if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(check_negative_values(client, ep, token).await);
            }

            // Price manipulation (financial POST/PUT/PATCH)
            if is_financial && matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(check_price_manipulation(client, ep, token).await);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn send_request(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> Option<u16> {
    let method = ep.method.parse().unwrap_or(reqwest::Method::GET);
    let mut builder = client.inner().request(method, &ep.full_url);

    if !token.is_empty() {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    if let Some(b) = body {
        builder = builder
            .header("Content-Type", "application/json")
            .body(b.to_string());
    }

    let req = builder.build().ok()?;
    let resp = client.send(req).await.ok()?;
    Some(resp.status().as_u16())
}

/// Returns true if the URL path looks like it contains a transactional action
/// worth probing for race conditions (heuristic: ends with a verb or noun).
fn is_mutation_endpoint(ep: &Endpoint) -> bool {
    let path = ep.path.to_lowercase();
    let verbs = ["submit", "create", "apply", "redeem", "buy", "pay", "confirm"];
    verbs.iter().any(|v| path.contains(v))
        || FINANCIAL_KEYWORDS.iter().any(|kw| path.contains(kw))
}

// ---------------------------------------------------------------------------
// Check: Rate Limit Bypass
// ---------------------------------------------------------------------------

async fn check_rate_limit(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    // Phase 1: rapid-fire with no header variation
    let mut successes = 0usize;
    for _ in 0..RATE_LIMIT_PROBE_COUNT {
        if let Some(status) = send_request(client, ep, token, &[], None).await {
            if status != 429 {
                successes += 1;
            }
        }
    }

    if successes == RATE_LIMIT_PROBE_COUNT {
        // All requests passed — no rate limiting detected
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

        // Phase 2: check if X-Forwarded-For rotation bypasses an existing rate limit
        // (only relevant if the first phase found a limit — but we report the base finding anyway)
        return vec![f];
    }

    // Rate limit exists — now test if X-Forwarded-For / User-Agent rotation bypasses it
    check_rate_limit_header_bypass(client, ep, token).await
}

async fn check_rate_limit_header_bypass(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    // Try X-Forwarded-For spoofing
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

    // Try User-Agent rotation
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

// ---------------------------------------------------------------------------
// Check: Race Condition
// ---------------------------------------------------------------------------

async fn check_race_condition(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    if !is_mutation_endpoint(ep) {
        return vec![];
    }

    // Fire RACE_PROBE_COUNT identical requests in parallel
    let mut handles = Vec::with_capacity(RACE_PROBE_COUNT);
    for _ in 0..RACE_PROBE_COUNT {
        let method = ep.method.parse().unwrap_or(reqwest::Method::POST);
        let url = ep.full_url.clone();
        let auth = if token.is_empty() {
            None
        } else {
            Some(format!("Bearer {}", token))
        };
        let inner = client.inner().clone();

        handles.push(tokio::spawn(async move {
            let mut builder = inner.request(method, &url);
            if let Some(ref h) = auth {
                builder = builder.header("Authorization", h);
            }
            builder = builder
                .header("Content-Type", "application/json")
                .body("{}");
            let req = builder.build().ok()?;
            let resp = inner.execute(req).await.ok()?;
            Some(resp.status().as_u16())
        }));
    }

    let mut success_count = 0usize;
    for handle in handles {
        if let Ok(Some(status)) = handle.await {
            if matches!(status, 200..=299) {
                success_count += 1;
            }
        }
    }

    // If more than half of parallel requests succeeded, flag race condition
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
        f.proof = format!(
            "{}/{} requêtes simultanées → HTTP 2xx",
            success_count, RACE_PROBE_COUNT
        );
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

// ---------------------------------------------------------------------------
// Check: Negative / Boundary Values
// ---------------------------------------------------------------------------

async fn check_negative_values(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let test_values: &[(&str, serde_json::Value)] = &[
        ("-1",           serde_json::json!(-1)),
        ("-0.01",        serde_json::json!(-0.01)),
        ("0",            serde_json::json!(0)),
        ("2147483647",   serde_json::json!(2147483647i64)),
        ("-2147483648",  serde_json::json!(-2147483648i64)),
        ("9999999999",   serde_json::json!(9999999999i64)),
    ];

    for field in NUMERIC_FIELD_NAMES {
        for (label, value) in test_values {
            let body = serde_json::json!({ (*field): value }).to_string();
            if let Some(status) =
                send_request(client, ep, token, &[], Some(&body)).await
            {
                if matches!(status, 200..=299) {
                    let mut f = Finding::new(
                        format!("Valeur invalide acceptée — champ `{}` = {}", field, label),
                        Severity::Medium,
                        6.5,
                        "business-logic".to_string(),
                        ep.full_url.clone(),
                        ep.method.clone(),
                    );
                    f.description = format!(
                        "L'endpoint {} {} a accepté la valeur {} pour le champ `{}` (HTTP {}). \
                         Des montants négatifs ou nuls peuvent entraîner des enrichissements \
                         injustifiés (crédits négatifs, remboursements frauduleux).",
                        ep.method, ep.full_url, label, field, status
                    );
                    f.proof = format!(
                        "Body: {{ \"{}\": {} }} → HTTP {}",
                        field, label, status
                    );
                    f.recommendation = format!(
                        "Valider que le champ `{}` est strictement positif côté serveur. \
                         Ne pas se fier uniquement à la validation côté client.",
                        field
                    );
                    f.cwe = Some("CWE-20".to_string());
                    f.references = vec![
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/".to_string(),
                    ];
                    return vec![f];
                }
            }
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Price Manipulation
// ---------------------------------------------------------------------------

async fn check_price_manipulation(
    client: &HttpClient,
    ep: &Endpoint,
    token: &str,
) -> Vec<Finding> {
    let price_fields = &["price", "amount", "total", "cost", "subtotal"];
    let manipulated_values: &[(&str, serde_json::Value)] = &[
        ("0",    serde_json::json!(0)),
        ("0.01", serde_json::json!(0.01)),
        ("-1",   serde_json::json!(-1)),
        ("1",    serde_json::json!(1)),
    ];

    // Baseline: empty body
    let baseline = send_request(client, ep, token, &[], Some("{}")).await;
    let baseline_status = baseline.unwrap_or(0);

    for field in price_fields {
        for (label, value) in manipulated_values {
            let body = serde_json::json!({ (*field): value }).to_string();
            if let Some(status) =
                send_request(client, ep, token, &[], Some(&body)).await
            {
                // Flag if the server accepts a suspiciously low price where baseline failed
                // OR accepts price=0/-1 with a success response
                let suspicious = matches!(status, 200..=299)
                    && (!matches!(baseline_status, 200..=299)
                        || value == &serde_json::json!(0)
                        || value == &serde_json::json!(-1));

                if suspicious {
                    let mut f = Finding::new(
                        format!("Price Manipulation — champ `{}` = {}", field, label),
                        Severity::High,
                        8.6,
                        "business-logic".to_string(),
                        ep.full_url.clone(),
                        ep.method.clone(),
                    );
                    f.description = format!(
                        "L'endpoint {} {} accepte un prix de {} pour le champ `{}` (HTTP {}). \
                         Un attaquant peut acheter des biens ou services à un prix arbitraire.",
                        ep.method, ep.full_url, label, field, status
                    );
                    f.proof = format!(
                        "Body: {{ \"{}\": {} }} → HTTP {}",
                        field, label, status
                    );
                    f.recommendation =
                        "Le prix doit être calculé et validé exclusivement côté serveur \
                         à partir du catalogue produit. Ne jamais accepter un prix \
                         fourni par le client."
                            .to_string();
                    f.cwe = Some("CWE-20".to_string());
                    f.references = vec![
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/".to_string(),
                    ];
                    return vec![f];
                }
            }
        }
    }

    vec![]
}
