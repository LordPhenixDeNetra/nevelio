use nevelio_core::types::Endpoint;

/// Follow hyperlinks and `href`/`url` fields found in JSON API responses.
/// Probes the first N discovered endpoints and extracts any API paths from their JSON bodies.
pub(super) async fn extract_json_links(
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
        let ct = resp
            .headers()
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
pub(super) fn extract_api_paths_from_json(body: &str, base_host: &str) -> Vec<String> {
    let mut paths = Vec::new();

    let Ok(val) = serde_json::from_str::<serde_json::Value>(body) else {
        return paths;
    };

    collect_json_paths(&val, base_host, &mut paths);
    paths
}

pub(super) fn collect_json_paths(
    val: &serde_json::Value,
    base_host: &str,
    out: &mut Vec<String>,
) {
    match val {
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                let k = key.to_lowercase();
                // Interesting keys that may contain URL/path values
                if [
                    "href", "url", "uri", "link", "path", "endpoint", "next", "prev",
                    "previous", "self", "first", "last", "related",
                ]
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

pub(super) fn extract_path_from_str(s: &str, base_host: &str) -> Option<String> {
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
