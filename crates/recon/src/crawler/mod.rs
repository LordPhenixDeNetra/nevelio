mod js;
mod json;
mod robots;

use anyhow::Result;
use nevelio_core::types::Endpoint;
use std::collections::HashSet;

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
/// When `stealth` is true (ScanProfile::Stealth), paths listed in `robots.txt`
/// are skipped. Additionally, JS files are crawled to discover extra API paths,
/// and versioned path variants are automatically probed.
pub async fn discover_endpoints(
    base_url: &str,
    client: &reqwest::Client,
    stealth: bool,
) -> Result<Vec<Endpoint>> {
    let base = base_url.trim_end_matches('/');
    tracing::info!("Crawling {} common paths on {}", WORDLIST.len(), base);

    // In stealth mode, respect robots.txt
    let disallowed: HashSet<String> = if stealth {
        robots::load_robots_disallowed(base, client).await
    } else {
        HashSet::new()
    };

    // Phase 1: wordlist probing
    let mut tasks = Vec::new();
    for &(path, method) in WORDLIST {
        if stealth && robots::is_disallowed(path, &disallowed) {
            tracing::debug!("[crawler] Skipping {} (robots.txt)", path);
            continue;
        }
        let url = format!("{}{}", base, path);
        let client = client.clone();
        let path = path.to_string();
        let method = method.to_string();
        tasks.push(tokio::spawn(async move {
            probe_path(client, url, path, method).await
        }));
    }

    let mut found: Vec<Endpoint> = Vec::new();
    for task in tasks {
        if let Ok(Some(ep)) = task.await {
            found.push(ep);
        }
    }

    // Phase 2: detect API versioning and expand versioned paths
    let discovered_paths: Vec<String> = found.iter().map(|e| e.path.clone()).collect();
    let extra_paths = robots::expand_versioned_paths(&discovered_paths);

    let mut version_tasks = Vec::new();
    for path in extra_paths {
        if stealth && robots::is_disallowed(&path, &disallowed) {
            continue;
        }
        let url = format!("{}{}", base, path);
        let client = client.clone();
        let method = "GET".to_string();
        version_tasks.push(tokio::spawn(async move {
            probe_path(client, url, path, method).await
        }));
    }
    for task in version_tasks {
        if let Ok(Some(ep)) = task.await {
            if !found
                .iter()
                .any(|e| e.path == ep.path && e.method == ep.method)
            {
                found.push(ep);
            }
        }
    }

    // Phase 3: extract URLs from JavaScript
    let js_paths = js::extract_js_urls(base, client).await;
    let mut js_tasks = Vec::new();
    for path in js_paths {
        if stealth && robots::is_disallowed(&path, &disallowed) {
            continue;
        }
        let url = format!("{}{}", base, path);
        let client = client.clone();
        let method = "GET".to_string();
        js_tasks.push(tokio::spawn(async move {
            probe_path(client, url, path, method).await
        }));
    }
    for task in js_tasks {
        if let Ok(Some(ep)) = task.await {
            if !found
                .iter()
                .any(|e| e.path == ep.path && e.method == ep.method)
            {
                found.push(ep);
            }
        }
    }

    // Phase 4: follow links found in JSON API responses
    let json_paths = json::extract_json_links(base, &found, client).await;
    let mut json_tasks = Vec::new();
    for path in json_paths {
        if stealth && robots::is_disallowed(&path, &disallowed) {
            continue;
        }
        if found.iter().any(|e| e.path == path) {
            continue;
        }
        let url = format!("{}{}", base, path);
        let c = client.clone();
        let method = "GET".to_string();
        json_tasks.push(tokio::spawn(async move {
            probe_path(c, url, path, method).await
        }));
    }
    for task in json_tasks {
        if let Ok(Some(ep)) = task.await {
            if !found
                .iter()
                .any(|e| e.path == ep.path && e.method == ep.method)
            {
                found.push(ep);
            }
        }
    }

    tracing::info!("Crawler found {} reachable endpoint(s)", found.len());
    Ok(found)
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

// ── Tests ─────────────────────────────────────────────────────────────────────

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

    #[test]
    fn expand_versioned_v1_paths() {
        let paths = vec!["/api/v1/users".to_string(), "/api/v1".to_string()];
        let extra = robots::expand_versioned_paths(&paths);
        assert!(extra.contains(&"/api/v2/users".to_string()));
        assert!(extra.contains(&"/api/v3/users".to_string()));
        assert!(extra.contains(&"/api/v2".to_string()));
    }

    #[test]
    fn expand_versioned_no_duplicates() {
        let paths = vec!["/api/v1/users".to_string(), "/api/v2/users".to_string()];
        let extra = robots::expand_versioned_paths(&paths);
        assert!(!extra.contains(&"/api/v2/users".to_string()));
    }

    #[test]
    fn extract_api_paths_from_js_detects_fetch() {
        let js = r#"fetch("/api/users").then(r => r.json())"#;
        let paths = js::extract_api_paths_from_js(js);
        assert!(
            paths.contains(&"/api/users".to_string()),
            "paths: {:?}",
            paths
        );
    }

    #[test]
    fn extract_api_paths_from_js_detects_axios() {
        let js = r#"axios.get("/v1/products").then(cb)"#;
        let paths = js::extract_api_paths_from_js(js);
        assert!(
            paths.contains(&"/v1/products".to_string()),
            "paths: {:?}",
            paths
        );
    }

    #[test]
    fn extract_api_paths_from_js_detects_string_literals() {
        let js = r#"const BASE = "/api/orders"; return fetch(BASE);"#;
        let paths = js::extract_api_paths_from_js(js);
        assert!(
            paths.contains(&"/api/orders".to_string()),
            "paths: {:?}",
            paths
        );
    }

    #[test]
    fn extract_api_paths_ignores_static() {
        let js = r#"import "/api/v1/styles.css";"#;
        let paths = js::extract_api_paths_from_js(js);
        assert!(!paths.contains(&"/api/v1/styles.css".to_string()));
    }

    #[test]
    fn is_disallowed_prefix_match() {
        let mut set = HashSet::new();
        set.insert("/admin/".to_string());
        assert!(robots::is_disallowed("/admin/users", &set));
        assert!(!robots::is_disallowed("/api/users", &set));
    }

    #[test]
    fn is_disallowed_exact_match() {
        let mut set = HashSet::new();
        set.insert("/private".to_string());
        assert!(robots::is_disallowed("/private", &set));
        assert!(!robots::is_disallowed("/private2", &set));
    }

    #[test]
    fn extract_script_srcs_finds_src() {
        let html =
            r#"<html><script src="/js/app.js"></script><script src='bundle.js'></script></html>"#;
        let srcs = js::extract_script_srcs(html);
        assert!(srcs.contains(&"/js/app.js".to_string()), "srcs: {:?}", srcs);
        assert!(srcs.contains(&"bundle.js".to_string()), "srcs: {:?}", srcs);
    }
}
