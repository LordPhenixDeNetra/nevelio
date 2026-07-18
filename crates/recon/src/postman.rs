mod insomnia;
#[cfg(test)]
mod tests;

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

// ── Public API ────────────────────────────────────────────────────────────────

pub fn parse_postman(path: &str) -> Result<Vec<Endpoint>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read file '{}': {}", path, e))?;

    let head = &content[..content.len().min(512)];

    if head.contains("_postman_schema") {
        parse_postman_collection(&content)
    } else if head.contains("__export_format") {
        insomnia::parse_insomnia_export(&content)
    } else {
        parse_postman_collection(&content).or_else(|_| insomnia::parse_insomnia_export(&content))
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
    tracing::info!(
        "[postman] Parsed {} endpoints from Postman collection",
        endpoints.len()
    );
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

    let (full_url, path) =
        if url_no_query.starts_with("http://") || url_no_query.starts_with("https://") {
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

// ── Shared helpers ────────────────────────────────────────────────────────────

pub(crate) fn resolve_vars(s: &str, vars: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
        result = result.replace(&format!("{{{{ {} }}}}", key), value);
    }
    result
}

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
