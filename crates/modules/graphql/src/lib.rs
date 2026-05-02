use async_trait::async_trait;
use std::time::Instant;

use nevelio_core::types::{Endpoint, Finding, Severity};
use nevelio_core::{AttackModule, HttpClient, ScanSession};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GraphQL introspection query — detects if schema introspection is enabled.
const INTROSPECTION_QUERY: &str =
    r#"{"query":"{ __schema { types { name } } }"}"#;

/// Deeply nested query — a 20-level nesting stresses query depth limits.
const DEPTH_QUERY: &str = r#"{"query":"{ a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } } } } } } } } } } } }"}"#;

/// Common GraphQL endpoint paths probed when no spec is provided.
const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/gql",
    "/graphql/v1",
];

const DEPTH_THRESHOLD_MS: u128 = 3_000;

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

pub struct GraphqlModule;

#[async_trait]
impl AttackModule for GraphqlModule {
    fn name(&self) -> &str {
        "graphql"
    }

    fn description(&self) -> &str {
        "Tests GraphQL introspection, field suggestions, and depth-based DoS"
    }

    async fn run(
        &self,
        _session: &ScanSession,
        client: &HttpClient,
        endpoints: &[Endpoint],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect candidate GraphQL endpoints from spec + probe common paths
        let graphql_endpoints = collect_graphql_endpoints(endpoints);

        for ep in &graphql_endpoints {
            if let Some(f) = check_introspection(client, ep).await {
                findings.push(f);
            }
            if let Some(f) = check_field_suggestions(client, ep).await {
                findings.push(f);
            }
            if let Some(f) = check_depth_dos(client, ep).await {
                findings.push(f);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a deduplicated list of GraphQL endpoint candidates.
/// Uses spec-provided endpoints that look like GraphQL, plus common probe paths
/// against the base URL of the first spec endpoint.
fn collect_graphql_endpoints(endpoints: &[Endpoint]) -> Vec<Endpoint> {
    let mut candidates: Vec<Endpoint> = endpoints
        .iter()
        .filter(|ep| {
            let p = ep.path.to_lowercase();
            p.contains("graphql") || p == "/query" || p == "/gql"
        })
        .cloned()
        .collect();

    // Derive base URL from the first available endpoint for probing
    if let Some(first) = endpoints.first() {
        let base = extract_base_url(&first.full_url);
        for path in GRAPHQL_PATHS {
            let full = format!("{}{}", base, path);
            if !candidates.iter().any(|c| c.full_url == full) {
                candidates.push(Endpoint {
                    method: "POST".to_string(),
                    path: path.to_string(),
                    full_url: full,
                    parameters: vec![],
                    auth_required: false,
                });
            }
        }
    }

    candidates
}

fn extract_base_url(url: &str) -> String {
    if let Some(idx) = url[url.find("://").map(|i| i + 3).unwrap_or(0)..]
        .find('/')
        .map(|i| i + url.find("://").map(|j| j + 3).unwrap_or(0))
    {
        url[..idx].to_string()
    } else {
        url.to_string()
    }
}

fn graphql_post(
    client: &HttpClient,
    ep: &Endpoint,
    body: &'static str,
) -> reqwest::Result<reqwest::Request> {
    client
        .inner()
        .post(&ep.full_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body)
        .build()
}

// ---------------------------------------------------------------------------
// Check: Introspection enabled
// ---------------------------------------------------------------------------

async fn check_introspection(client: &HttpClient, ep: &Endpoint) -> Option<Finding> {
    let Ok(req) = graphql_post(client, ep, INTROSPECTION_QUERY) else {
        return None;
    };
    let Ok(resp) = client.send(req).await else {
        return None;
    };

    // Only flag if the endpoint actually responded (not a 404)
    if resp.status().as_u16() == 404 {
        return None;
    }

    let body = resp.text().await.unwrap_or_default();

    // Introspection is enabled if the response contains schema data
    if !body.contains("__schema") && !body.contains("queryType") {
        return None;
    }

    let mut f = Finding::new(
        "GraphQL Introspection Enabled",
        Severity::Medium,
        5.3,
        "graphql",
        ep.full_url.clone(),
        "POST",
    );
    f.cvss_vector = Some("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string());
    f.description =
        "L'introspection GraphQL est activée en production. Un attaquant peut récupérer \
         le schéma complet de l'API (tous les types, champs, mutations, abonnements) \
         sans authentification, ce qui facilite grandement les attaques ciblées."
            .to_string();
    f.proof = format!(
        "Requête: {}\nLe corps de réponse contient __schema ou queryType",
        INTROSPECTION_QUERY
    );
    f.recommendation =
        "Désactiver l'introspection en production. Dans Apollo Server : \
         `introspection: false`. Dans Hasura : restreindre via des règles de rôle. \
         Autoriser l'introspection uniquement aux équipes internes via IP allowlist."
            .to_string();
    f.cwe = Some("CWE-200".to_string());
    f.references = vec![
        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/".to_string(),
        "https://graphql.org/learn/introspection/".to_string(),
    ];

    Some(f)
}

// ---------------------------------------------------------------------------
// Check: Field suggestions leak schema info
// ---------------------------------------------------------------------------

async fn check_field_suggestions(client: &HttpClient, ep: &Endpoint) -> Option<Finding> {
    // Intentional typo — if suggestions are enabled, the error reveals valid field names
    let body = r#"{"query":"{ usr { id } }"}"#;
    let Ok(req) = graphql_post(client, ep, body) else {
        return None;
    };
    let Ok(resp) = client.send(req).await else {
        return None;
    };

    if resp.status().as_u16() == 404 {
        return None;
    }

    let text = resp.text().await.unwrap_or_default();
    if !text.contains("Did you mean") && !text.contains("did you mean") {
        return None;
    }

    let mut f = Finding::new(
        "GraphQL Field Suggestions — Fuite du schéma",
        Severity::Low,
        3.7,
        "graphql",
        ep.full_url.clone(),
        "POST",
    );
    f.cvss_vector = Some("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string());
    f.description =
        "Le serveur GraphQL retourne des suggestions de correction (\"Did you mean…\") \
         pour les champs invalides. Ces messages révèlent des noms de champs réels du schéma, \
         même si l'introspection est désactivée."
            .to_string();
    f.proof = format!(
        "Payload: {body}\nRéponse contient \"Did you mean\" — noms de champs divulgués"
    );
    f.recommendation =
        "Désactiver les suggestions dans le moteur GraphQL. Dans Apollo Server : \
         `formatError: (err) => {{ delete err.extensions.suggestions; return err; }}`."
            .to_string();
    f.cwe = Some("CWE-209".to_string());
    f.references = vec![
        "https://lab.wallarm.com/graphql-batching-attack/".to_string(),
    ];

    Some(f)
}

// ---------------------------------------------------------------------------
// Check: Depth-based DoS
// ---------------------------------------------------------------------------

async fn check_depth_dos(client: &HttpClient, ep: &Endpoint) -> Option<Finding> {
    let Ok(req) = graphql_post(client, ep, DEPTH_QUERY) else {
        return None;
    };

    let start = Instant::now();
    let result = client.send(req).await;
    let elapsed = start.elapsed().as_millis();

    // Flag if: timeout/error (DoS) OR very slow response on a 200
    let triggered = result.is_err() || elapsed >= DEPTH_THRESHOLD_MS;
    if !triggered {
        // Also check if the server returned a 500 (query complexity crash)
        if let Ok(resp) = result {
            if resp.status().as_u16() != 500 {
                return None;
            }
        } else {
            return None;
        }
    }

    let mut f = Finding::new(
        "GraphQL Depth DoS — Requête profondément imbriquée acceptée",
        Severity::Medium,
        5.9,
        "graphql",
        ep.full_url.clone(),
        "POST",
    );
    f.cvss_vector = Some("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string());
    f.description = format!(
        "Le serveur a mis {}ms pour répondre à une requête imbriquée sur 20 niveaux. \
         Sans limite de profondeur, un attaquant peut créer des requêtes exponentiellement \
         coûteuses qui saturent le serveur (CPU/mémoire).",
        elapsed
    );
    f.proof = format!(
        "Requête 20 niveaux d'imbrication → {}ms de délai",
        elapsed
    );
    f.recommendation =
        "Implémenter une limite de profondeur de requête (ex: max 10 niveaux). \
         Dans Apollo Server : plugin `graphql-depth-limit`. \
         Activer également la limite de complexité de requête."
            .to_string();
    f.cwe = Some("CWE-400".to_string());
    f.references = vec![
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/".to_string(),
        "https://www.apollographql.com/docs/apollo-server/performance/cache-hints/".to_string(),
    ];

    Some(f)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_base_url_simple() {
        assert_eq!(
            extract_base_url("https://api.example.com/v1/users"),
            "https://api.example.com"
        );
    }

    #[test]
    fn extract_base_url_no_path() {
        assert_eq!(
            extract_base_url("https://api.example.com"),
            "https://api.example.com"
        );
    }

    #[test]
    fn collect_graphql_endpoints_from_spec() {
        let ep = Endpoint {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            full_url: "https://api.example.com/graphql".to_string(),
            parameters: vec![],
            auth_required: false,
        };
        let result = collect_graphql_endpoints(&[ep]);
        // Should include the spec endpoint + probe paths (deduplicated)
        assert!(result.iter().any(|e| e.path == "/graphql"));
    }

    #[test]
    fn collect_graphql_endpoints_probes_common_paths() {
        let ep = Endpoint {
            method: "GET".to_string(),
            path: "/users".to_string(),
            full_url: "https://api.example.com/users".to_string(),
            parameters: vec![],
            auth_required: false,
        };
        let result = collect_graphql_endpoints(&[ep]);
        // Should include probed paths
        assert!(result.iter().any(|e| e.path == "/graphql"));
        assert!(result.iter().any(|e| e.path == "/api/graphql"));
    }

    #[test]
    fn introspection_query_is_valid_json() {
        let v: serde_json::Result<serde_json::Value> = serde_json::from_str(INTROSPECTION_QUERY);
        assert!(v.is_ok(), "introspection query must be valid JSON");
    }

    #[test]
    fn depth_query_is_valid_json() {
        let v: serde_json::Result<serde_json::Value> = serde_json::from_str(DEPTH_QUERY);
        assert!(v.is_ok(), "depth query must be valid JSON");
    }
}
