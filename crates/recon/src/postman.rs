use anyhow::Result;
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};
use serde::Deserialize;
use std::collections::HashMap;

// ── Postman v2.1 structs ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PostmanCollection {
    #[serde(default)]
    item: Vec<PostmanItem>,
    #[serde(default)]
    variable: Vec<PostmanVar>,
}

/// Postman items can be either a folder (has `item`) or a request (has `request`).
#[derive(Debug, Deserialize)]
struct PostmanItem {
    request: Option<PostmanRequest>,
    #[serde(default)]
    item: Vec<PostmanItem>,
}

#[derive(Debug, Deserialize)]
struct PostmanRequest {
    method: Option<String>,
    url: Option<PostmanUrl>,
    body: Option<PostmanBody>,
}

/// URL can be an object or a plain string in older collections.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PostmanUrl {
    Object(PostmanUrlObject),
    Raw(String),
}

#[derive(Debug, Deserialize)]
struct PostmanUrlObject {
    raw: Option<String>,
    #[serde(default)]
    query: Vec<PostmanQuery>,
}

#[derive(Debug, Deserialize)]
struct PostmanQuery {
    key: Option<String>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Deserialize)]
struct PostmanBody {
    mode: Option<String>,
    raw: Option<String>,
    #[serde(default)]
    urlencoded: Vec<PostmanFormParam>,
    #[serde(default)]
    formdata: Vec<PostmanFormParam>,
}

#[derive(Debug, Deserialize)]
struct PostmanFormParam {
    key: Option<String>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Deserialize)]
struct PostmanVar {
    key: Option<String>,
    value: Option<String>,
}

// ── Insomnia v4 structs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct InsomniaExport {
    resources: Vec<serde_json::Value>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a Postman v2.1 collection or Insomnia v4 export.
///
/// Format is auto-detected from file content. The `--spec` flag accepts both.
pub fn parse_postman(path: &str) -> Result<Vec<Endpoint>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read file '{}': {}", path, e))?;

    let head = &content[..content.len().min(512)];

    if head.contains("_postman_schema") {
        parse_postman_collection(&content)
    } else if head.contains("__export_format") {
        parse_insomnia_export(&content)
    } else {
        // Fall back: try Postman then Insomnia
        parse_postman_collection(&content)
            .or_else(|_| parse_insomnia_export(&content))
    }
}

// ── Postman ───────────────────────────────────────────────────────────────────

fn parse_postman_collection(raw: &str) -> Result<Vec<Endpoint>> {
    let col: PostmanCollection = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("Invalid Postman collection: {}", e))?;

    let vars: HashMap<String, String> = col
        .variable
        .iter()
        .filter_map(|v| Some((v.key.clone()?, v.value.clone().unwrap_or_default())))
        .collect();

    let endpoints = collect_postman_items(&col.item, &vars);
    tracing::info!("[postman] Parsed {} endpoints from Postman collection", endpoints.len());
    Ok(endpoints)
}

fn collect_postman_items(items: &[PostmanItem], vars: &HashMap<String, String>) -> Vec<Endpoint> {
    let mut result = Vec::new();
    for item in items {
        if !item.item.is_empty() {
            result.extend(collect_postman_items(&item.item, vars));
        }
        if let Some(req) = &item.request {
            if let Some(ep) = postman_request_to_endpoint(req, vars) {
                result.push(ep);
            }
        }
    }
    result
}

fn postman_request_to_endpoint(
    req: &PostmanRequest,
    vars: &HashMap<String, String>,
) -> Option<Endpoint> {
    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();

    let (raw_url, mut parameters) = match &req.url {
        Some(PostmanUrl::Object(obj)) => {
            let raw = obj.raw.as_deref().unwrap_or("").to_string();
            let qp: Vec<Parameter> = obj
                .query
                .iter()
                .filter(|q| !q.disabled)
                .filter_map(|q| {
                    q.key.as_ref().map(|k| Parameter {
                        name: k.clone(),
                        location: ParameterLocation::Query,
                        required: false,
                        schema: None,
                    })
                })
                .collect();
            (raw, qp)
        }
        Some(PostmanUrl::Raw(s)) => (s.clone(), vec![]),
        None => return None,
    };

    let resolved = resolve_vars(&raw_url, vars);
    let url_no_query = resolved.split('?').next().unwrap_or(&resolved);

    let (full_url, path) = if url_no_query.starts_with("http://")
        || url_no_query.starts_with("https://")
    {
        let p = extract_path_from_url(url_no_query);
        (url_no_query.to_string(), p)
    } else {
        (url_no_query.to_string(), url_no_query.to_string())
    };

    if full_url.is_empty() {
        return None;
    }

    if let Some(body) = &req.body {
        extract_postman_body_params(body, &mut parameters);
    }

    Some(Endpoint {
        method,
        path,
        full_url,
        parameters,
        auth_required: false,
    })
}

fn extract_postman_body_params(body: &PostmanBody, params: &mut Vec<Parameter>) {
    match body.mode.as_deref() {
        Some("raw") => {
            if let Some(raw) = &body.raw {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) {
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
            }
        }
        Some("urlencoded") => {
            for p in &body.urlencoded {
                if !p.disabled {
                    if let Some(k) = &p.key {
                        params.push(Parameter {
                            name: k.clone(),
                            location: ParameterLocation::Body,
                            required: false,
                            schema: None,
                        });
                    }
                }
            }
        }
        Some("formdata") => {
            for p in &body.formdata {
                if !p.disabled {
                    if let Some(k) = &p.key {
                        params.push(Parameter {
                            name: k.clone(),
                            location: ParameterLocation::Body,
                            required: false,
                            schema: None,
                        });
                    }
                }
            }
        }
        _ => {}
    }
}

// ── Insomnia ──────────────────────────────────────────────────────────────────

fn parse_insomnia_export(raw: &str) -> Result<Vec<Endpoint>> {
    let export: InsomniaExport = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("Invalid Insomnia export: {}", e))?;

    // First pass: collect env variables
    let mut vars: HashMap<String, String> = HashMap::new();
    for res in &export.resources {
        if res.get("_type").and_then(|t| t.as_str()) == Some("environment") {
            if let Some(data) = res.get("data").and_then(|d| d.as_object()) {
                for (k, v) in data {
                    if let Some(s) = v.as_str() {
                        vars.insert(k.clone(), s.to_string());
                    }
                }
            }
        }
    }

    // Second pass: extract requests
    let mut endpoints = Vec::new();
    for res in &export.resources {
        if res.get("_type").and_then(|t| t.as_str()) != Some("request") {
            continue;
        }

        let method = res
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("GET")
            .to_uppercase();

        let raw_url = res
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        let resolved = resolve_vars(&raw_url, &vars);
        let url_no_query = resolved.split('?').next().unwrap_or(&resolved).to_string();

        if url_no_query.is_empty() {
            continue;
        }

        let (full_url, path) = if url_no_query.starts_with("http://")
            || url_no_query.starts_with("https://")
        {
            let p = extract_path_from_url(&url_no_query);
            (url_no_query.clone(), p)
        } else {
            (url_no_query.clone(), url_no_query.clone())
        };

        let mut parameters: Vec<Parameter> = Vec::new();

        // Query parameters
        if let Some(arr) = res.get("parameters").and_then(|p| p.as_array()) {
            for param in arr {
                let disabled = param
                    .get("disabled")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);
                if !disabled {
                    if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                        parameters.push(Parameter {
                            name: name.to_string(),
                            location: ParameterLocation::Query,
                            required: false,
                            schema: None,
                        });
                    }
                }
            }
        }

        // Body
        if let Some(body) = res.get("body") {
            if let Some(text) = body.get("text").and_then(|t| t.as_str()) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                    if let Some(obj) = json.as_object() {
                        for key in obj.keys() {
                            parameters.push(Parameter {
                                name: key.clone(),
                                location: ParameterLocation::Body,
                                required: false,
                                schema: None,
                            });
                        }
                    }
                }
            }
        }

        endpoints.push(Endpoint {
            method,
            path,
            full_url,
            parameters,
            auth_required: false,
        });
    }

    tracing::info!("[insomnia] Parsed {} endpoints from Insomnia export", endpoints.len());
    Ok(endpoints)
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Resolve `{{key}}` (Postman) and `{{ key }}` (Insomnia) variable references.
pub(crate) fn resolve_vars(s: &str, vars: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
        result = result.replace(&format!("{{{{ {} }}}}", key), value);
    }
    result
}

/// Extract the path component from an absolute URL.
pub(crate) fn extract_path_from_url(url: &str) -> String {
    if let Some(pos) = url.find("://") {
        let after = &url[pos + 3..];
        if let Some(slash) = after.find('/') {
            return after[slash..].to_string();
        }
        return "/".to_string();
    }
    url.to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_vars_postman_style() {
        let vars: HashMap<String, String> =
            [("base_url".to_string(), "https://api.example.com".to_string())].into();
        assert_eq!(
            resolve_vars("{{base_url}}/users", &vars),
            "https://api.example.com/users"
        );
    }

    #[test]
    fn resolve_vars_insomnia_style() {
        let vars: HashMap<String, String> =
            [("base_url".to_string(), "https://api.example.com".to_string())].into();
        assert_eq!(
            resolve_vars("{{ base_url }}/users", &vars),
            "https://api.example.com/users"
        );
    }

    #[test]
    fn extract_path_from_url_with_path() {
        assert_eq!(
            extract_path_from_url("https://api.example.com/v1/users"),
            "/v1/users"
        );
    }

    #[test]
    fn extract_path_from_url_no_path() {
        assert_eq!(extract_path_from_url("https://api.example.com"), "/");
    }

    #[test]
    fn parse_postman_minimal_collection() {
        let json = r#"{
            "info": { "_postman_schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
            "item": [
                {
                    "name": "Get Users",
                    "request": {
                        "method": "GET",
                        "url": { "raw": "https://api.example.com/users", "query": [] }
                    }
                }
            ],
            "variable": []
        }"#;
        let tmp = std::env::temp_dir().join("nevelio_test_postman.json");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].method, "GET");
        assert_eq!(eps[0].path, "/users");
    }

    #[test]
    fn parse_postman_resolves_variables() {
        let json = r#"{
            "info": { "_postman_schema": "..." },
            "item": [
                {
                    "name": "Get Users",
                    "request": {
                        "method": "GET",
                        "url": { "raw": "{{base_url}}/users", "query": [] }
                    }
                }
            ],
            "variable": [
                { "key": "base_url", "value": "https://api.example.com" }
            ]
        }"#;
        let tmp = std::env::temp_dir().join("nevelio_test_postman_vars.json");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].full_url, "https://api.example.com/users");
    }

    #[test]
    fn parse_postman_nested_folders() {
        let json = r#"{
            "info": { "_postman_schema": "..." },
            "item": [
                {
                    "name": "Users",
                    "item": [
                        {
                            "name": "List",
                            "request": { "method": "GET", "url": { "raw": "https://api.example.com/users", "query": [] } }
                        },
                        {
                            "name": "Create",
                            "request": { "method": "POST", "url": { "raw": "https://api.example.com/users", "query": [] } }
                        }
                    ]
                }
            ],
            "variable": []
        }"#;
        let tmp = std::env::temp_dir().join("nevelio_test_postman_folders.json");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 2);
    }

    #[test]
    fn parse_insomnia_export() {
        let json = r#"{
            "_type": "export",
            "__export_format": 4,
            "__export_date": "2024-01-01",
            "__export_source": "insomnia.desktop.app",
            "resources": [
                {
                    "_type": "environment",
                    "_id": "env_1",
                    "data": { "base_url": "https://api.example.com" }
                },
                {
                    "_type": "request",
                    "_id": "req_1",
                    "method": "GET",
                    "url": "{{ base_url }}/products",
                    "parameters": [{ "name": "page", "value": "1", "disabled": false }]
                }
            ]
        }"#;
        let tmp = std::env::temp_dir().join("nevelio_test_insomnia.json");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].method, "GET");
        assert_eq!(eps[0].path, "/products");
        assert_eq!(eps[0].parameters.len(), 1);
        assert_eq!(eps[0].parameters[0].name, "page");
    }

    #[test]
    fn parse_postman_url_as_string() {
        let json = r#"{
            "info": { "_postman_schema": "..." },
            "item": [
                {
                    "name": "Ping",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/ping"
                    }
                }
            ],
            "variable": []
        }"#;
        let tmp = std::env::temp_dir().join("nevelio_test_postman_str_url.json");
        std::fs::write(&tmp, json).unwrap();
        let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].path, "/ping");
    }
}
