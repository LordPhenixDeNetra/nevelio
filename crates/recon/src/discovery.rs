use anyhow::Result;
use nevelio_core::types::Endpoint;

/// Discover endpoints from a base URL without a spec.
/// Phase 1 stub — returns only the root endpoint.
pub async fn discover_endpoints(base_url: &str) -> Result<Vec<Endpoint>> {
    tracing::info!("Discovering endpoints from: {}", base_url);
    Ok(vec![Endpoint {
        method: "GET".to_string(),
        path: "/".to_string(),
        full_url: base_url.to_string(),
        parameters: vec![],
        auth_required: false,
    }])
}
