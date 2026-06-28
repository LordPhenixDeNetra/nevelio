use anyhow::Result;
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};
use serde::Deserialize;
use std::collections::HashMap;

use super::{extract_path_from_url, resolve_vars};

#[derive(Debug, Deserialize)]
struct InsomniaExport {
    resources: Vec<serde_json::Value>,
}

pub(super) fn parse_insomnia_export(raw: &str) -> Result<Vec<Endpoint>> {
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
            .get("method").and_then(|m| m.as_str())
            .unwrap_or("GET").to_uppercase();

        let raw_url = res
            .get("url").and_then(|u| u.as_str())
            .unwrap_or("").to_string();

        let resolved = resolve_vars(&raw_url, &vars);
        let url_no_query = resolved.split('?').next().unwrap_or(&resolved).to_string();

        if url_no_query.is_empty() { continue; }

        let (full_url, path) = if url_no_query.starts_with("http://")
            || url_no_query.starts_with("https://")
        {
            let p = extract_path_from_url(&url_no_query);
            (url_no_query.clone(), p)
        } else {
            (url_no_query.clone(), url_no_query.clone())
        };

        let mut parameters: Vec<Parameter> = Vec::new();

        if let Some(arr) = res.get("parameters").and_then(|p| p.as_array()) {
            for param in arr {
                let disabled = param.get("disabled")
                    .and_then(|d| d.as_bool()).unwrap_or(false);
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

        endpoints.push(Endpoint { method, path, full_url, parameters, auth_required: false });
    }

    tracing::info!("[insomnia] Parsed {} endpoints from Insomnia export", endpoints.len());
    Ok(endpoints)
}
