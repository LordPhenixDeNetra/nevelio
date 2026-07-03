use anyhow::{Context, Result};
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};


// ---------------------------------------------------------------------------
// AsyncAPI 2.x / 3.x spec parser
// Supports JSON and YAML. Discovers WebSocket / HTTP / MQTT channels.
// ---------------------------------------------------------------------------

pub fn parse_asyncapi(path: &str) -> Result<Vec<Endpoint>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read AsyncAPI spec: {}", path))?;
    parse_asyncapi_content(&content)
        .with_context(|| format!("Failed to parse AsyncAPI spec: {}", path))
}

pub fn parse_asyncapi_content(content: &str) -> Result<Vec<Endpoint>> {
    // Try JSON first, then YAML (reuse serde_yaml which is already a workspace dep)
    let raw: serde_json::Value = if content.trim_start().starts_with('{') {
        serde_json::from_str(content)?
    } else {
        // Parse YAML → JSON via serde round-trip
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(content)
            .map_err(|e| anyhow::anyhow!("YAML parse error: {}", e))?;
        let json_str = serde_json::to_string(&yaml_val)
            .map_err(|e| anyhow::anyhow!("YAML→JSON conversion error: {}", e))?;
        serde_json::from_str(&json_str)?
    };

    // Detect version
    let version_str = raw.get("asyncapi")
        .and_then(|v| v.as_str())
        .unwrap_or("2.0.0");

    if version_str.starts_with('3') {
        parse_v3(&raw)
    } else {
        parse_v2(&raw)
    }
}

// ---------------------------------------------------------------------------
// AsyncAPI 2.x
// ---------------------------------------------------------------------------

fn parse_v2(raw: &serde_json::Value) -> Result<Vec<Endpoint>> {
    let mut endpoints = Vec::new();

    // Resolve server base URLs
    let servers = extract_servers_v2(raw);
    let base = servers.first().cloned().unwrap_or_default();

    let channels = match raw.get("channels").and_then(|c| c.as_object()) {
        Some(c) => c,
        None => return Ok(endpoints),
    };

    for (channel_path, channel_def) in channels {
        let full_url = build_url(&base, channel_path);

        // Collect parameters from channel definition
        let params = extract_channel_params(channel_def);

        // Each operation (subscribe/publish) becomes an endpoint
        for op in ["subscribe", "publish"] {
            if let Some(op_def) = channel_def.get(op) {
                let method = if op == "publish" { "POST" } else { "GET" };
                let mut ep = Endpoint {
                    method: method.to_string(),
                    path: channel_path.clone(),
                    full_url: full_url.clone(),
                    parameters: params.clone(),
                    auth_required: has_security(op_def),
                };

                // Add bindings info as header parameter (for WS/MQTT metadata)
                if let Some(binding) = extract_binding_protocol(channel_def) {
                    ep.parameters.push(Parameter {
                        name: format!("__protocol:{}", binding),
                        location: ParameterLocation::Header,
                        required: false,
                        schema: None,
                    });
                }

                endpoints.push(ep);
            }
        }
    }

    Ok(endpoints)
}

fn extract_servers_v2(raw: &serde_json::Value) -> Vec<String> {
    let mut urls = Vec::new();
    let servers = match raw.get("servers").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return urls,
    };

    for (_name, server) in servers {
        let url = server.get("url").and_then(|u| u.as_str()).unwrap_or("");
        let protocol = server.get("protocol").and_then(|p| p.as_str()).unwrap_or("ws");

        let full_url = if url.starts_with("http") || url.starts_with("ws") {
            url.to_string()
        } else {
            let scheme = match protocol {
                "mqtt" | "mqtts" => format!("{}://", protocol),
                "amqp" | "amqps" => format!("{}://", protocol),
                "wss" => "wss://".to_string(),
                _ => "ws://".to_string(),
            };
            format!("{}{}", scheme, url)
        };

        urls.push(full_url);
    }

    urls
}

// ---------------------------------------------------------------------------
// AsyncAPI 3.x
// ---------------------------------------------------------------------------

fn parse_v3(raw: &serde_json::Value) -> Result<Vec<Endpoint>> {
    let mut endpoints = Vec::new();

    // v3: servers are objects with `host` + `protocol` + `pathname`
    let base = extract_server_base_v3(raw);

    // v3: channels are top-level, operations reference channels
    let channels = match raw.get("channels").and_then(|c| c.as_object()) {
        Some(c) => c,
        None => return Ok(endpoints),
    };

    let operations = raw.get("operations").and_then(|o| o.as_object());

    for (channel_name, channel_def) in channels {
        let address = channel_def.get("address")
            .and_then(|a| a.as_str())
            .unwrap_or(channel_name.as_str());

        let full_url = build_url(&base, address);
        let params = extract_channel_params(channel_def);

        // Find operations that reference this channel
        let ops_for_channel: Vec<(&str, &serde_json::Value)> = operations
            .iter()
            .flat_map(|o| o.iter())
            .filter(|(_, op)| {
                op.get("channel")
                    .and_then(|c| c.get("$ref").or(c.as_str().map(|_| c)))
                    .and_then(|r| r.as_str())
                    .map(|r| r.contains(channel_name.as_str()))
                    .unwrap_or(false)
            })
            .map(|(k, v)| (k.as_str(), v))
            .collect();

        if ops_for_channel.is_empty() {
            // No explicit operation — add a generic endpoint
            endpoints.push(Endpoint {
                method: "GET".to_string(),
                path: address.to_string(),
                full_url: full_url.clone(),
                parameters: params.clone(),
                auth_required: false,
            });
        }

        for (op_name, op_def) in ops_for_channel {
            let action = op_def.get("action").and_then(|a| a.as_str()).unwrap_or(op_name);
            let method = if action == "send" { "POST" } else { "GET" };

            endpoints.push(Endpoint {
                method: method.to_string(),
                path: address.to_string(),
                full_url: full_url.clone(),
                parameters: params.clone(),
                auth_required: has_security(op_def),
            });
        }
    }

    Ok(endpoints)
}

fn extract_server_base_v3(raw: &serde_json::Value) -> String {
    let servers = match raw.get("servers").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return String::new(),
    };

    for (_name, server) in servers {
        let host = server.get("host").and_then(|h| h.as_str()).unwrap_or("");
        let protocol = server.get("protocol").and_then(|p| p.as_str()).unwrap_or("ws");
        let pathname = server.get("pathname").and_then(|p| p.as_str()).unwrap_or("");

        if !host.is_empty() {
            let scheme = match protocol {
                "wss" | "https" => "wss",
                _ => "ws",
            };
            return format!("{}://{}{}", scheme, host, pathname);
        }
    }

    String::new()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

fn extract_channel_params(channel_def: &serde_json::Value) -> Vec<Parameter> {
    let mut params = Vec::new();

    if let Some(parameters) = channel_def.get("parameters").and_then(|p| p.as_object()) {
        for (name, _) in parameters {
            params.push(Parameter {
                name: name.clone(),
                location: ParameterLocation::Path,
                required: true,
                schema: None,
            });
        }
    }

    params
}

fn extract_binding_protocol(channel_def: &serde_json::Value) -> Option<&'static str> {
    if let Some(bindings) = channel_def.get("bindings").and_then(|b| b.as_object()) {
        if let Some(key) = bindings.keys().next() {
            return Some(match key.as_str() {
                "ws" | "websockets" => "websocket",
                "mqtt" => "mqtt",
                "amqp" => "amqp",
                "kafka" => "kafka",
                "http" => "http",
                _ => "unknown",
            });
        }
    }
    None
}

fn has_security(op_def: &serde_json::Value) -> bool {
    op_def.get("security")
        .and_then(|s| s.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ASYNCAPI_V2: &str = r#"
asyncapi: "2.6.0"
info:
  title: My API
  version: "1.0"
servers:
  production:
    url: api.example.com
    protocol: wss
channels:
  /user/signedup:
    subscribe:
      message:
        payload:
          type: object
    publish:
      message:
        payload:
          type: object
  /chat/{roomId}:
    parameters:
      roomId:
        schema:
          type: string
    subscribe:
      message:
        payload:
          type: string
"#;

    #[test]
    fn parse_asyncapi_v2_channels() {
        let endpoints = parse_asyncapi_content(ASYNCAPI_V2).expect("should parse");
        // /user/signedup has subscribe+publish = 2, /chat/{roomId} has subscribe = 1
        assert!(endpoints.len() >= 2, "got {} endpoints", endpoints.len());
    }

    #[test]
    fn parse_asyncapi_v2_base_url() {
        let endpoints = parse_asyncapi_content(ASYNCAPI_V2).expect("should parse");
        let has_wss = endpoints.iter().any(|e| e.full_url.contains("api.example.com"));
        assert!(has_wss, "endpoints: {:?}", endpoints.iter().map(|e| &e.full_url).collect::<Vec<_>>());
    }

    #[test]
    fn parse_asyncapi_v2_path_params() {
        let endpoints = parse_asyncapi_content(ASYNCAPI_V2).expect("should parse");
        let chat = endpoints.iter().find(|e| e.path.contains("roomId")).expect("chat endpoint");
        assert!(!chat.parameters.is_empty());
    }

    #[test]
    fn parse_nonexistent_file_returns_error() {
        assert!(parse_asyncapi("/nonexistent.yaml").is_err());
    }
}
