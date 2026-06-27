use anyhow::Result;
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};
use serde::Deserialize;
use std::collections::HashSet;

// ── HAR 1.2 structs ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct HarFile {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    #[serde(rename = "queryString", default)]
    query_string: Vec<HarParam>,
    #[serde(rename = "postData")]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarParam {
    name: String,
    #[allow(dead_code)]
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(rename = "mimeType", default)]
    mime_type: String,
    text: Option<String>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a HAR (HTTP Archive) file and return deduplicated API endpoints.
pub fn parse_har(path: &str) -> Result<Vec<Endpoint>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read HAR file '{}': {}", path, e))?;

    let har: HarFile = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Invalid HAR format in '{}': {}", path, e))?;

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut endpoints = Vec::new();

    for entry in har.log.entries {
        let req = entry.request;

        if !is_api_request(&req.url) {
            continue;
        }

        let (base, path_str) = split_url(&req.url);
        let normalized = normalize_path(&path_str);
        let key = (req.method.to_uppercase(), normalized.clone());

        if !seen.insert(key) {
            continue;
        }

        let mut parameters: Vec<Parameter> = req
            .query_string
            .iter()
            .map(|p| Parameter {
                name: p.name.clone(),
                location: ParameterLocation::Query,
                required: false,
                schema: None,
            })
            .collect();

        if let Some(post_data) = req.post_data {
            extract_body_params(&post_data, &mut parameters);
        }

        let full_url = format!("{}{}", base, path_str);
        endpoints.push(Endpoint {
            method: req.method.to_uppercase(),
            path: normalized,
            full_url,
            parameters,
            auth_required: false,
        });
    }

    tracing::info!("[har] Parsed {} unique endpoints", endpoints.len());
    Ok(endpoints)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns (scheme+host, path) stripping query string and fragment.
pub(crate) fn split_url(url: &str) -> (String, String) {
    let url = url.split('#').next().unwrap_or(url);
    let url = url.split('?').next().unwrap_or(url);

    if let Some(pos) = url.find("://") {
        let after_scheme = &url[pos + 3..];
        if let Some(slash) = after_scheme.find('/') {
            let base = url[..pos + 3 + slash].to_string();
            let path = after_scheme[slash..].to_string();
            return (base, path);
        }
        return (url.to_string(), "/".to_string());
    }
    ("".to_string(), url.to_string())
}

/// True if the URL looks like an API call (not a static asset).
pub(crate) fn is_api_request(url: &str) -> bool {
    if url.starts_with("data:") {
        return false;
    }
    let path = url.split('?').next().unwrap_or(url);
    const STATIC: &[&str] = &[
        ".css", ".js", ".mjs", ".ts",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".map", ".br", ".gz", ".html", ".htm",
        ".mp4", ".mp3", ".ogg", ".wav", ".pdf",
    ];
    !STATIC.iter().any(|ext| path.ends_with(ext))
}

/// Replace purely numeric segments and UUID-like segments with `{id}`.
pub(crate) fn normalize_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    path.split('/')
        .map(|seg| {
            if seg.is_empty() {
                seg.to_string()
            } else if seg.chars().all(|c| c.is_ascii_digit()) || is_uuid_like(seg) {
                "{id}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_uuid_like(s: &str) -> bool {
    s.len() == 36
        && s.chars().filter(|c| *c == '-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn extract_body_params(post_data: &HarPostData, params: &mut Vec<Parameter>) {
    let mime = &post_data.mime_type;
    let Some(text) = &post_data.text else { return };

    if mime.contains("json") {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = json.as_object() {
                for key in obj.keys() {
                    params.push(Parameter {
                        name: key.clone(),
                        location: ParameterLocation::Body,
                        required: false,
                        schema: None,
                    });
                }
            }
        }
    } else if mime.contains("form") {
        for pair in text.split('&') {
            if let Some((k, _)) = pair.split_once('=') {
                if !k.is_empty() {
                    params.push(Parameter {
                        name: k.to_string(),
                        location: ParameterLocation::Body,
                        required: false,
                        schema: None,
                    });
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_api_request_rejects_static() {
        assert!(!is_api_request("https://example.com/style.css"));
        assert!(!is_api_request("https://example.com/app.js"));
        assert!(!is_api_request("https://example.com/logo.png"));
        assert!(!is_api_request("https://example.com/font.woff2"));
    }

    #[test]
    fn is_api_request_accepts_api_paths() {
        assert!(is_api_request("https://example.com/api/users"));
        assert!(is_api_request("https://example.com/users"));
        assert!(is_api_request("https://example.com/v1/products?page=1"));
    }

    #[test]
    fn normalize_path_replaces_numbers() {
        assert_eq!(normalize_path("/users/123/orders"), "/users/{id}/orders");
    }

    #[test]
    fn normalize_path_replaces_uuids() {
        assert_eq!(
            normalize_path("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{id}"
        );
    }

    #[test]
    fn normalize_path_preserves_non_id_segments() {
        assert_eq!(normalize_path("/api/v1/users"), "/api/v1/users");
    }

    #[test]
    fn split_url_extracts_path_and_base() {
        let (base, path) = split_url("https://api.example.com/users?limit=10");
        assert_eq!(base, "https://api.example.com");
        assert_eq!(path, "/users");
    }

    #[test]
    fn split_url_no_path() {
        let (base, path) = split_url("https://api.example.com");
        assert_eq!(base, "https://api.example.com");
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_har_minimal() {
        let json = r#"{"log":{"entries":[{"request":{"method":"GET","url":"https://api.example.com/users","queryString":[]}}]}}"#;
        let tmp = std::env::temp_dir().join("nevelio_test_minimal.har");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_har(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].method, "GET");
        assert_eq!(eps[0].path, "/users");
    }

    #[test]
    fn parse_har_deduplicates() {
        let json = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://api.example.com/users","queryString":[]}},
            {"request":{"method":"GET","url":"https://api.example.com/users?page=2","queryString":[{"name":"page","value":"2"}]}}
        ]}}"#;
        let tmp = std::env::temp_dir().join("nevelio_test_dedup.har");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_har(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1, "Same method+path should deduplicate");
    }

    #[test]
    fn parse_har_normalizes_ids() {
        let json = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://api.example.com/users/123","queryString":[]}},
            {"request":{"method":"GET","url":"https://api.example.com/users/456","queryString":[]}}
        ]}}"#;
        let tmp = std::env::temp_dir().join("nevelio_test_norm.har");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_har(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1, "Both normalize to /users/{{id}}");
        assert_eq!(eps[0].path, "/users/{id}");
    }

    #[test]
    fn parse_har_filters_static() {
        let json = r#"{"log":{"entries":[
            {"request":{"method":"GET","url":"https://example.com/style.css","queryString":[]}},
            {"request":{"method":"GET","url":"https://example.com/api/users","queryString":[]}}
        ]}}"#;
        let tmp = std::env::temp_dir().join("nevelio_test_filter.har");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_har(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].path, "/api/users");
    }
}
