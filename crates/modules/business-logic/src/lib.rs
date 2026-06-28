mod rate_limit;
mod race;
mod negative;
mod price;

use async_trait::async_trait;
use nevelio_core::types::{Endpoint, Finding};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Constants (pub(crate) so sub-modules can use them)
// ---------------------------------------------------------------------------

pub(crate) const RATE_LIMIT_PROBE_COUNT: usize = 20;
pub(crate) const RACE_PROBE_COUNT: usize = 10;

pub(crate) const FINANCIAL_KEYWORDS: &[&str] = &[
    "order", "payment", "checkout", "purchase", "cart", "buy",
    "coupon", "promo", "discount", "voucher", "redeem",
    "transfer", "withdraw", "deposit", "refund", "invoice",
    "subscription", "charge", "billing",
];

pub(crate) const NUMERIC_FIELD_NAMES: &[&str] = &[
    "price", "amount", "quantity", "qty", "total", "cost",
    "fee", "discount", "coupon_value", "points", "credits",
    "balance", "subtotal", "tax", "tip",
];

pub(crate) const XFF_VALUES: &[&str] = &[
    "127.0.0.1", "10.0.0.1", "192.168.1.1",
    "172.16.0.1", "1.1.1.1", "8.8.8.8",
];

pub(crate) const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "PostmanRuntime/7.32.1",
    "Go-http-client/1.1",
];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct BusinessLogicModule;

#[async_trait]
impl AttackModule for BusinessLogicModule {
    fn name(&self) -> &str { "business-logic" }

    fn description(&self) -> &str {
        "Tests rate limit bypass, race conditions, negative values, and workflow bypass"
    }

    async fn run(&self, session: &ScanSession, client: &HttpClient, endpoints: &[Endpoint]) -> Vec<Finding> {
        let token = session.config.auth_token.as_deref().unwrap_or("");
        let mut findings = Vec::new();

        for ep in endpoints {
            let is_financial = FINANCIAL_KEYWORDS
                .iter()
                .any(|kw| ep.full_url.to_lowercase().contains(kw));

            findings.extend(rate_limit::check_rate_limit(client, ep, token).await);

            if is_financial && matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(race::check_race_condition(client, ep, token).await);
            }

            if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(negative::check_negative_values(client, ep, token).await);
            }

            if is_financial && matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(price::check_price_manipulation(client, ep, token).await);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (pub(crate) so sub-modules can use them)
// ---------------------------------------------------------------------------

pub(crate) async fn send_request(
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
        builder = builder.header("Content-Type", "application/json").body(b.to_string());
    }

    let req = builder.build().ok()?;
    let resp = client.send(req).await.ok()?;
    Some(resp.status().as_u16())
}

pub(crate) fn is_mutation_endpoint(ep: &Endpoint) -> bool {
    let path = ep.path.to_lowercase();
    let verbs = ["submit", "create", "apply", "redeem", "buy", "pay", "confirm"];
    verbs.iter().any(|v| path.contains(v))
        || FINANCIAL_KEYWORDS.iter().any(|kw| path.contains(kw))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        assert!(FINANCIAL_KEYWORDS.contains(&"payment"));
        assert!(FINANCIAL_KEYWORDS.contains(&"checkout"));
        assert!(FINANCIAL_KEYWORDS.contains(&"refund"));
        assert!(FINANCIAL_KEYWORDS.contains(&"coupon"));
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
