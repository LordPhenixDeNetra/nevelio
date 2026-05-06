use anyhow::Result;
use nevelio_core::types::Endpoint;

/// Common API paths to probe during discovery (path, method).
const WORDLIST: &[(&str, &str)] = &[
    // Root and versioned bases
    ("/", "GET"),
    ("/api", "GET"),
    ("/api/v1", "GET"),
    ("/api/v2", "GET"),
    ("/api/v3", "GET"),
    ("/v1", "GET"),
    ("/v2", "GET"),
    ("/v3", "GET"),
    // Health / status
    ("/health", "GET"),
    ("/healthz", "GET"),
    ("/status", "GET"),
    ("/ping", "GET"),
    ("/ready", "GET"),
    ("/live", "GET"),
    // Metrics / observability
    ("/metrics", "GET"),
    ("/actuator", "GET"),
    ("/actuator/health", "GET"),
    ("/actuator/info", "GET"),
    ("/actuator/env", "GET"),
    ("/actuator/mappings", "GET"),
    ("/actuator/beans", "GET"),
    ("/actuator/loggers", "GET"),
    // API documentation
    ("/swagger-ui.html", "GET"),
    ("/swagger-ui/", "GET"),
    ("/swagger/", "GET"),
    ("/swagger.json", "GET"),
    ("/swagger.yaml", "GET"),
    ("/api-docs", "GET"),
    ("/api-docs/v1", "GET"),
    ("/openapi.json", "GET"),
    ("/openapi.yaml", "GET"),
    ("/openapi", "GET"),
    ("/redoc", "GET"),
    ("/docs", "GET"),
    // GraphQL
    ("/graphql", "POST"),
    ("/graphql", "GET"),
    ("/graphiql", "GET"),
    ("/playground", "GET"),
    // Admin / internal
    ("/admin", "GET"),
    ("/admin/users", "GET"),
    ("/internal", "GET"),
    ("/management", "GET"),
    ("/console", "GET"),
    // Debug / sensitive
    ("/.env", "GET"),
    ("/debug", "GET"),
    ("/phpinfo.php", "GET"),
    ("/info", "GET"),
    ("/server-status", "GET"),
    ("/server-info", "GET"),
    ("/.git/HEAD", "GET"),
    ("/config", "GET"),
    ("/config.json", "GET"),
    ("/robots.txt", "GET"),
    ("/sitemap.xml", "GET"),
    // Common API resources
    ("/users", "GET"),
    ("/user", "GET"),
    ("/accounts", "GET"),
    ("/profile", "GET"),
    ("/me", "GET"),
    ("/auth/login", "POST"),
    ("/auth/register", "POST"),
    ("/auth/refresh", "POST"),
    ("/login", "POST"),
    ("/register", "POST"),
];

/// Probe common API paths and return those that respond (non-404 status).
///
/// Phase 2: basic discovery. Phase 3 will add JS analysis and recursive crawl.
pub async fn discover_endpoints(
    base_url: &str,
    client: &reqwest::Client,
) -> Result<Vec<Endpoint>> {
    let base = base_url.trim_end_matches('/');
    tracing::info!("Crawling {} common paths on {}", WORDLIST.len(), base);

    let mut found = Vec::new();
    let mut tasks = Vec::new();

    for &(path, method) in WORDLIST {
        let url = format!("{}{}", base, path);
        let client = client.clone();
        let path = path.to_string();
        let method = method.to_string();

        tasks.push(tokio::spawn(async move {
            probe_path(client, url.clone(), path, method).await
        }));
    }

    for task in tasks {
        if let Ok(Some(endpoint)) = task.await {
            found.push(endpoint);
        }
    }

    tracing::info!("Crawler found {} reachable endpoint(s)", found.len());
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_not_empty() {
        assert!(!WORDLIST.is_empty());
    }

    #[test]
    fn wordlist_entries_have_leading_slash() {
        for (path, _method) in WORDLIST {
            assert!(
                path.starts_with('/'),
                "Wordlist path must start with '/': {}",
                path
            );
        }
    }

    #[test]
    fn wordlist_methods_are_valid() {
        const VALID: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        for (path, method) in WORDLIST {
            assert!(
                VALID.contains(method),
                "Invalid HTTP method '{}' for path '{}'",
                method,
                path
            );
        }
    }

    #[test]
    fn probe_url_is_built_correctly() {
        let base = "https://api.example.com";
        let path = "/health";
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        assert_eq!(url, "https://api.example.com/health");
    }

    #[test]
    fn base_url_trailing_slash_is_trimmed() {
        let base = "https://api.example.com/";
        let path = "/health";
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        assert_eq!(url, "https://api.example.com/health");
    }
}

async fn probe_path(
    client: reqwest::Client,
    url: String,
    path: String,
    method: String,
) -> Option<Endpoint> {
    let req = match method.as_str() {
        "POST" => client.post(&url),
        _ => client.get(&url),
    }
    .timeout(std::time::Duration::from_secs(5))
    .build()
    .ok()?;

    match client.execute(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Consider anything that is not 404 or 410 as "found"
            if status != 404 && status != 410 {
                tracing::debug!("[crawler] {} {} → {}", method, url, status);
                Some(Endpoint {
                    method: method.clone(),
                    path: path.clone(),
                    full_url: url,
                    parameters: vec![],
                    auth_required: status == 401 || status == 403,
                })
            } else {
                None
            }
        }
        Err(e) => {
            tracing::debug!("[crawler] {} {} → error: {}", method, url, e);
            None
        }
    }
}
