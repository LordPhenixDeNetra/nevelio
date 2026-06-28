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
    let disallowed = if stealth {
        load_robots_disallowed(base, client).await
    } else {
        HashSet::new()
    };

    // Phase 1: wordlist probing
    let mut tasks = Vec::new();
    for &(path, method) in WORDLIST {
        if stealth && is_disallowed(path, &disallowed) {
            tracing::debug!("[crawler] Skipping {} (robots.txt)", path);
            continue;
        }
        let url = format!("{}{}", base, path);
        let client = client.clone();
        let path = path.to_string();
        let method = method.to_string();
        tasks.push(tokio::spawn(
            async move { probe_path(client, url, path, method).await },
        ));
    }

    let mut found: Vec<Endpoint> = Vec::new();
    for task in tasks {
        if let Ok(Some(ep)) = task.await {
            found.push(ep);
        }
    }

    // Phase 2: detect API versioning and expand versioned paths
    let discovered_paths: Vec<String> = found.iter().map(|e| e.path.clone()).collect();
    let extra_paths = expand_versioned_paths(&discovered_paths);

    let mut version_tasks = Vec::new();
    for path in extra_paths {
        if stealth && is_disallowed(&path, &disallowed) {
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
            if !found.iter().any(|e| e.path == ep.path && e.method == ep.method) {
                found.push(ep);
            }
        }
    }

    // Phase 3: extract URLs from JavaScript
    let js_paths = extract_js_urls(base, client).await;
    let mut js_tasks = Vec::new();
    for path in js_paths {
        if stealth && is_disallowed(&path, &disallowed) {
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
            if !found.iter().any(|e| e.path == ep.path && e.method == ep.method) {
                found.push(ep);
            }
        }
    }

    // Phase 4: follow links found in JSON API responses
    let json_paths = extract_json_links(base, &found, client).await;
    let mut json_tasks = Vec::new();
    for path in json_paths {
        if stealth && is_disallowed(&path, &disallowed) {
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
            if !found.iter().any(|e| e.path == ep.path && e.method == ep.method) {
                found.push(ep);
            }
        }
    }

    tracing::info!("Crawler found {} reachable endpoint(s)", found.len());
    Ok(found)
}

/// Follow hyperlinks and `href`/`url` fields found in JSON API responses.
/// Probes the first N discovered endpoints and extracts any API paths from their JSON bodies.
async fn extract_json_links(
    base: &str,
    endpoints: &[Endpoint],
    client: &reqwest::Client,
) -> Vec<String> {
    const MAX_PROBE: usize = 10;
    let mut paths: Vec<String> = Vec::new();
    let base_host = base.trim_end_matches('/');

    for ep in endpoints.iter().take(MAX_PROBE) {
        let resp = client
            .get(&ep.full_url)
            .timeout(std::time::Duration::from_secs(5))
            .header("Accept", "application/json")
            .send()
            .await;

        let Ok(resp) = resp else { continue };

        // Only follow JSON responses
        let ct = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("json") {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        let extracted = extract_api_paths_from_json(&body, base_host);
        for p in extracted {
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }

    paths
}

/// Extract API path strings from a JSON body.
/// Looks for `"href"`, `"url"`, `"uri"`, `"link"`, `"path"`, `"endpoint"` fields
/// and `"links"` / `"_links"` (HAL) / `"next"` / `"prev"` pagination fields.
fn extract_api_paths_from_json(body: &str, base_host: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let Ok(val) = serde_json::from_str::<serde_json::Value>(body) else {
        return paths;
    };

    collect_json_paths(&val, base_host, &mut paths);
    paths
}

fn collect_json_paths(val: &serde_json::Value, base_host: &str, out: &mut Vec<String>) {
    match val {
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                let k = key.to_lowercase();
                // Interesting keys that may contain URL/path values
                if ["href", "url", "uri", "link", "path", "endpoint", "next", "prev",
                    "previous", "self", "first", "last", "related"]
                    .contains(&k.as_str())
                {
                    if let Some(s) = v.as_str() {
                        if let Some(path) = extract_path_from_str(s, base_host) {
                            if !out.contains(&path) {
                                out.push(path);
                            }
                        }
                    }
                }
                collect_json_paths(v, base_host, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_paths(item, base_host, out);
            }
        }
        _ => {}
    }
}

fn extract_path_from_str(s: &str, base_host: &str) -> Option<String> {
    // Absolute URL matching our host
    if s.starts_with("http") {
        if s.contains(base_host) {
            // Strip the host part, keep the path
            let after_host = s
                .find(base_host)
                .map(|i| &s[i + base_host.len()..])?;
            let path = after_host.split('?').next().unwrap_or(after_host);
            if path.starts_with('/') && path.len() > 1 {
                return Some(path.to_string());
            }
        }
        return None;
    }

    // Relative path starting with /
    if s.starts_with('/') && s.len() > 1 {
        let path = s.split('?').next().unwrap_or(s);
        // Must look like an API path (no file extensions)
        let has_ext = [".html", ".css", ".js", ".png", ".jpg", ".ico", ".svg"]
            .iter()
            .any(|e| path.ends_with(e));
        if !has_ext {
            return Some(path.to_string());
        }
    }

    None
}

// ── robots.txt ────────────────────────────────────────────────────────────────

async fn load_robots_disallowed(base: &str, client: &reqwest::Client) -> HashSet<String> {
    let url = format!("{}/robots.txt", base);
    let mut disallowed = HashSet::new();

    let text = match client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => return disallowed,
    };

    for line in text.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_prefix("Disallow:") {
            let path = path.split_whitespace().next().unwrap_or("").trim();
            if !path.is_empty() {
                disallowed.insert(path.to_string());
            }
        }
    }

    tracing::debug!("[crawler] robots.txt: {} disallowed paths", disallowed.len());
    disallowed
}

fn is_disallowed(path: &str, disallowed: &HashSet<String>) -> bool {
    disallowed.iter().any(|d| {
        if d.ends_with('/') {
            path.starts_with(d.as_str())
        } else {
            path == d.as_str() || path.starts_with(&format!("{}/", d))
        }
    })
}

// ── API versioning ────────────────────────────────────────────────────────────

/// If `/api/v1/...` was found, generate variants for v2–v4.
fn expand_versioned_paths(paths: &[String]) -> Vec<String> {
    let mut extra = Vec::new();
    for path in paths {
        if path.contains("/v1") {
            for v in &["2", "3", "4"] {
                let candidate = path.replacen("/v1", &format!("/v{}", v), 1);
                if !paths.contains(&candidate) && !extra.contains(&candidate) {
                    extra.push(candidate);
                }
            }
        }
    }
    extra
}

// ── JavaScript URL extraction ─────────────────────────────────────────────────

/// Fetch the root page, find `<script src>` tags, download local JS files,
/// and extract API-looking paths from `fetch()`, `axios.*()`, and string literals.
async fn extract_js_urls(base: &str, client: &reqwest::Client) -> Vec<String> {
    let html = match client
        .get(base)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => return vec![],
    };

    let script_srcs = extract_script_srcs(&html);
    let mut api_paths: Vec<String> = Vec::new();

    for src in script_srcs.iter().take(10) {
        if src.starts_with("http://") || src.starts_with("https://") {
            continue; // skip CDN scripts
        }
        let js_url = format!("{}/{}", base, src.trim_start_matches('/'));

        let content = match client
            .get(&js_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            _ => continue,
        };

        api_paths.extend(extract_api_paths_from_js(&content));
    }

    api_paths.sort();
    api_paths.dedup();
    api_paths
}

/// Extract `src` attribute values from `<script>` tags.
fn extract_script_srcs(html: &str) -> Vec<String> {
    let mut srcs = Vec::new();
    let mut search = html;

    while let Some(tag_pos) = search.to_lowercase().find("<script") {
        let after = &search[tag_pos..];
        let tag_end = after.find('>').unwrap_or(after.len());
        let tag_content = &after[..tag_end];

        if let Some(src) = extract_attr(tag_content, "src") {
            if !src.is_empty() {
                srcs.push(src);
            }
        }

        search = &search[tag_pos + 7..]; // advance past "<script"
    }

    srcs
}

/// Extract an HTML attribute value (single or double quotes).
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let search_dq = format!("{}=\"", attr);
    let search_sq = format!("{}='", attr);

    if let Some(pos) = tag.to_lowercase().find(&search_dq) {
        let after = &tag[pos + search_dq.len()..];
        let end = after.find('"').unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    if let Some(pos) = tag.to_lowercase().find(&search_sq) {
        let after = &tag[pos + search_sq.len()..];
        let end = after.find('\'').unwrap_or(after.len());
        return Some(after[..end].to_string());
    }

    None
}

/// Extract API-looking paths from JS source code.
pub(crate) fn extract_api_paths_from_js(js: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Patterns: fetch("PATH"), axios.METHOD("PATH")
    let call_prefixes: &[&str] = &[
        "fetch(\"",
        "fetch('",
        "axios.get(\"",
        "axios.post(\"",
        "axios.put(\"",
        "axios.delete(\"",
        "axios.patch(\"",
        "axios.get('",
        "axios.post('",
        "axios.put('",
        "axios.delete('",
        "axios.patch('",
    ];

    for &prefix in call_prefixes {
        let quote = if prefix.ends_with('"') { '"' } else { '\'' };
        let mut search = js;
        while let Some(pos) = search.find(prefix) {
            search = &search[pos + prefix.len()..];
            if let Some(end) = search.find(quote) {
                let candidate = &search[..end];
                if is_api_path_candidate(candidate) {
                    paths.push(candidate.to_string());
                }
                search = &search[end..];
            }
        }
    }

    // String literals: "/api/...", "/v1/...", "/v2/..."
    let path_prefixes: &[(&str, char)] = &[
        ("\"/api/", '"'),
        ("'/api/", '\''),
        ("\"/v1/", '"'),
        ("'/v1/", '\''),
        ("\"/v2/", '"'),
        ("'/v2/", '\''),
        ("\"/v3/", '"'),
        ("'/v3/", '\''),
    ];

    for &(prefix, quote) in path_prefixes {
        let mut search = js;
        while let Some(pos) = search.find(prefix) {
            // The path starts after the opening quote
            search = &search[pos + 1..];
            if let Some(end) = search.find(quote) {
                let candidate = &search[..end];
                if is_api_path_candidate(candidate) {
                    paths.push(candidate.to_string());
                }
                search = &search[end + 1..];
            }
        }
    }

    paths.sort();
    paths.dedup();
    paths
}

fn is_api_path_candidate(s: &str) -> bool {
    s.starts_with('/')
        && s.len() > 2
        && !s.contains(' ')
        && !s.contains('\n')
        && !s.ends_with(".js")
        && !s.ends_with(".css")
        && !s.ends_with(".html")
}

// ── Low-level probe ───────────────────────────────────────────────────────────

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
        let extra = expand_versioned_paths(&paths);
        assert!(extra.contains(&"/api/v2/users".to_string()));
        assert!(extra.contains(&"/api/v3/users".to_string()));
        assert!(extra.contains(&"/api/v2".to_string()));
    }

    #[test]
    fn expand_versioned_no_duplicates() {
        let paths = vec![
            "/api/v1/users".to_string(),
            "/api/v2/users".to_string(),
        ];
        let extra = expand_versioned_paths(&paths);
        assert!(!extra.contains(&"/api/v2/users".to_string()));
    }

    #[test]
    fn extract_api_paths_from_js_detects_fetch() {
        let js = r#"fetch("/api/users").then(r => r.json())"#;
        let paths = extract_api_paths_from_js(js);
        assert!(paths.contains(&"/api/users".to_string()), "paths: {:?}", paths);
    }

    #[test]
    fn extract_api_paths_from_js_detects_axios() {
        let js = r#"axios.get("/v1/products").then(cb)"#;
        let paths = extract_api_paths_from_js(js);
        assert!(paths.contains(&"/v1/products".to_string()), "paths: {:?}", paths);
    }

    #[test]
    fn extract_api_paths_from_js_detects_string_literals() {
        let js = r#"const BASE = "/api/orders"; return fetch(BASE);"#;
        let paths = extract_api_paths_from_js(js);
        assert!(paths.contains(&"/api/orders".to_string()), "paths: {:?}", paths);
    }

    #[test]
    fn extract_api_paths_ignores_static() {
        let js = r#"import "/api/v1/styles.css";"#;
        let paths = extract_api_paths_from_js(js);
        assert!(!paths.contains(&"/api/v1/styles.css".to_string()));
    }

    #[test]
    fn is_disallowed_prefix_match() {
        let mut set = HashSet::new();
        set.insert("/admin/".to_string());
        assert!(is_disallowed("/admin/users", &set));
        assert!(!is_disallowed("/api/users", &set));
    }

    #[test]
    fn is_disallowed_exact_match() {
        let mut set = HashSet::new();
        set.insert("/private".to_string());
        assert!(is_disallowed("/private", &set));
        assert!(!is_disallowed("/private2", &set));
    }

    #[test]
    fn extract_script_srcs_finds_src() {
        let html = r#"<html><script src="/js/app.js"></script><script src='bundle.js'></script></html>"#;
        let srcs = extract_script_srcs(html);
        assert!(srcs.contains(&"/js/app.js".to_string()), "srcs: {:?}", srcs);
        assert!(srcs.contains(&"bundle.js".to_string()), "srcs: {:?}", srcs);
    }
}
