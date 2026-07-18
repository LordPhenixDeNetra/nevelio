/// MCP (Model Context Protocol) server — exposes Nevelio tools to AI orchestrators.
///
/// Transport: stdio (stdin → requests, stdout → responses)
/// Protocol:  JSON-RPC 2.0  ·  MCP version 2024-11-05
///
/// Compatible with Claude Desktop, Continue.dev, and any MCP-capable client.
///
/// Usage:
///   nevelio mcp serve --target https://api.example.com --accept-legal
///
/// Claude Desktop config (~/.config/claude/claude_desktop_config.json):
///   {
///     "mcpServers": {
///       "nevelio": {
///         "command": "nevelio",
///         "args": ["mcp", "serve", "--target", "https://api.example.com", "--accept-legal"]
///       }
///     }
///   }
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "nevelio";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── CLI args ──────────────────────────────────────────────────────────────────

#[derive(Debug, clap::Args)]
#[command(about = "Démarre un serveur MCP exposant les outils Nevelio aux agents IA")]
pub struct McpArgs {
    #[arg(
        long,
        value_name = "URL",
        help = "URL de base de l'API cible (ex: https://api.example.com)"
    )]
    pub target: Option<String>,

    #[arg(
        long,
        value_name = "SECS",
        default_value = "30",
        help = "Timeout des requêtes HTTP en secondes"
    )]
    pub timeout: u64,
}

pub async fn handle_mcp(args: McpArgs, accept_legal: bool) -> Result<()> {
    let state = Arc::new(Mutex::new(McpState {
        target: args.target,
        accept_legal,
        timeout_secs: args.timeout,
        findings: Vec::new(),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .user_agent("nevelio-mcp/0.1")
            .build()?,
    }));

    run_server(state).await
}

// ── Server state ──────────────────────────────────────────────────────────────

struct McpState {
    target: Option<String>,
    accept_legal: bool,
    #[allow(dead_code)]
    timeout_secs: u64, // stored for reference; timeout is baked into the client
    findings: Vec<Value>,
    client: reqwest::Client,
}

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl RpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ── Main server loop ──────────────────────────────────────────────────────────

async fn run_server(state: Arc<Mutex<McpState>>) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response_opt = match serde_json::from_str::<RpcRequest>(&line) {
            Err(e) => Some(RpcResponse::err(None, -32700, format!("Parse error: {e}"))),
            Ok(req) => {
                let is_notification = req.id.is_none();
                let resp = dispatch(req, Arc::clone(&state)).await;
                // Notifications must not receive a response
                if is_notification {
                    None
                } else {
                    resp
                }
            }
        };

        if let Some(resp) = response_opt {
            let mut json = serde_json::to_string(&resp)?;
            json.push('\n');
            stdout.write_all(json.as_bytes()).await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

// ── Method dispatch ───────────────────────────────────────────────────────────

async fn dispatch(req: RpcRequest, state: Arc<Mutex<McpState>>) -> Option<RpcResponse> {
    let id = req.id.clone();

    let result = match req.method.as_str() {
        "initialize" => Some(handle_initialize(&req.params)),
        "notifications/initialized" => None, // notification — no response
        "tools/list" => Some(handle_tools_list()),
        "tools/call" => Some(handle_tools_call(&req.params, state).await),
        "ping" => Some(Ok(json!({}))),
        _ => Some(Err((-32601, format!("Method '{}' not found", req.method)))),
    };

    result.map(|r| match r {
        Ok(v) => RpcResponse::ok(id, v),
        Err((code, m)) => RpcResponse::err(id, code, m),
    })
}

// ── MCP method handlers ───────────────────────────────────────────────────────

fn handle_initialize(_params: &Value) -> Result<Value, (i32, String)> {
    Ok(json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name":    SERVER_NAME,
            "version": SERVER_VERSION
        }
    }))
}

fn handle_tools_list() -> Result<Value, (i32, String)> {
    Ok(json!({
        "tools": [
            {
                "name": "list_endpoints",
                "description": "Découvre les endpoints d'une API cible par crawling.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "URL de base de l'API (ex: https://api.example.com). Optionnel si --target est passé au démarrage."
                        },
                        "stealth": {
                            "type": "boolean",
                            "description": "Mode discret — moins de requêtes, délai entre chaque."
                        }
                    },
                    "required": []
                }
            },
            {
                "name": "probe_endpoint",
                "description": "Envoie une requête HTTP à un endpoint et retourne status, headers, body.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url":     { "type": "string", "description": "URL complète à sonder" },
                        "method":  { "type": "string", "description": "Méthode HTTP (GET, POST, PUT, DELETE, PATCH, OPTIONS)", "default": "GET" },
                        "headers": { "type": "object", "description": "Headers additionnels" },
                        "body":    { "type": "string", "description": "Corps de la requête (pour POST/PUT/PATCH)" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "report_finding",
                "description": "Enregistre une vulnérabilité détectée.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title":          { "type": "string" },
                        "severity":       { "type": "string", "enum": ["critical", "high", "medium", "low", "info"] },
                        "endpoint":       { "type": "string" },
                        "description":    { "type": "string" },
                        "recommendation": { "type": "string" },
                        "proof":          { "type": "string" }
                    },
                    "required": ["title", "severity", "endpoint", "description"]
                }
            },
            {
                "name": "finish",
                "description": "Termine la session et retourne le rapport complet des findings.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "summary": { "type": "string", "description": "Résumé de l'analyse" }
                    },
                    "required": ["summary"]
                }
            }
        ]
    }))
}

async fn handle_tools_call(
    params: &Value,
    state: Arc<Mutex<McpState>>,
) -> Result<Value, (i32, String)> {
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "Paramètre 'name' manquant".to_string()))?;
    let args = &params["arguments"];

    match name {
        "list_endpoints" => tool_list_endpoints(args, state).await,
        "probe_endpoint" => tool_probe_endpoint(args, state).await,
        "report_finding" => tool_report_finding(args, state),
        "finish" => tool_finish(args, state),
        other => Err((-32602, format!("Outil inconnu : '{}'", other))),
    }
}

// ── Tool implementations ──────────────────────────────────────────────────────

async fn tool_list_endpoints(
    args: &Value,
    state: Arc<Mutex<McpState>>,
) -> Result<Value, (i32, String)> {
    let (target, client, stealth) = {
        let s = state.lock().unwrap();
        let t = args["target"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| s.target.clone())
            .ok_or((
                -32602,
                "Paramètre 'target' requis (ou démarrez avec --target URL)".to_string(),
            ))?;
        let c = s.client.clone();
        let st = args["stealth"].as_bool().unwrap_or(false);
        (t, c, st)
    };

    let endpoints = nevelio_recon::discover_endpoints(&target, &client, stealth)
        .await
        .map_err(|e| (-32603, format!("Crawling échoué : {e}")))?;

    let ep_list: Vec<Value> = endpoints
        .iter()
        .map(|ep| {
            json!({
                "method": ep.method,
                "path":   ep.path,
                "url":    ep.full_url,
            })
        })
        .collect();

    Ok(mcp_text(format!(
        "Découverts {} endpoints sur {}:\n{}",
        ep_list.len(),
        target,
        serde_json::to_string_pretty(&ep_list).unwrap_or_default()
    )))
}

async fn tool_probe_endpoint(
    args: &Value,
    state: Arc<Mutex<McpState>>,
) -> Result<Value, (i32, String)> {
    let (accept_legal, client) = {
        let s = state.lock().unwrap();
        (s.accept_legal, s.client.clone())
    };

    if !accept_legal {
        return Err((
            -32603,
            "Démarrez le serveur avec --accept-legal pour activer l'envoi de requêtes HTTP."
                .to_string(),
        ));
    }

    let url = args["url"]
        .as_str()
        .ok_or((-32602, "Paramètre 'url' requis".to_string()))?;
    let method = args["method"].as_str().unwrap_or("GET").to_uppercase();

    let mut req = match method.as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
        "HEAD" => client.head(url),
        other => return Err((-32602, format!("Méthode HTTP non supportée : {}", other))),
    };

    if let Some(headers) = args["headers"].as_object() {
        for (k, v) in headers {
            if let Some(val) = v.as_str() {
                req = req.header(k.as_str(), val);
            }
        }
    }

    if let Some(body) = args["body"].as_str() {
        req = req.body(body.to_string());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| (-32603, format!("Requête échouée : {e}")))?;

    let status = resp.status().as_u16();
    let hdrs: Value = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();

    let body = resp.text().await.unwrap_or_default();
    let body_preview = if body.len() > 2000 {
        format!("{}…[tronqué {} octets]", &body[..2000], body.len() - 2000)
    } else {
        body
    };

    Ok(mcp_text(format!(
        "Status: {}\n\nHeaders:\n{}\n\nBody:\n{}",
        status,
        serde_json::to_string_pretty(&hdrs).unwrap_or_default(),
        body_preview,
    )))
}

fn tool_report_finding(args: &Value, state: Arc<Mutex<McpState>>) -> Result<Value, (i32, String)> {
    let title = args["title"]
        .as_str()
        .ok_or((-32602, "Paramètre 'title' requis".to_string()))?;

    let finding = json!({
        "title":          title,
        "severity":       args["severity"].as_str().unwrap_or("info"),
        "endpoint":       args["endpoint"].as_str().unwrap_or(""),
        "description":    args["description"].as_str().unwrap_or(""),
        "recommendation": args["recommendation"].as_str().unwrap_or(""),
        "proof":          args["proof"].as_str().unwrap_or(""),
    });

    let count = {
        let mut s = state.lock().unwrap();
        s.findings.push(finding);
        s.findings.len()
    };

    Ok(mcp_text(format!(
        "Finding enregistré ({} au total).",
        count
    )))
}

fn tool_finish(args: &Value, state: Arc<Mutex<McpState>>) -> Result<Value, (i32, String)> {
    let summary = args["summary"].as_str().unwrap_or("Analyse terminée.");

    let findings = {
        let s = state.lock().unwrap();
        s.findings.clone()
    };

    let report = json!({
        "summary":  summary,
        "total":    findings.len(),
        "findings": findings,
    });

    Ok(mcp_text(format!(
        "Rapport final ({} findings) :\n{}",
        findings.len(),
        serde_json::to_string_pretty(&report).unwrap_or_default()
    )))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Wraps a text response in MCP's `content[{type:"text", text:...}]` envelope.
fn mcp_text(text: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_contains_four_tools() {
        let result = handle_tools_list().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"list_endpoints"));
        assert!(names.contains(&"probe_endpoint"));
        assert!(names.contains(&"report_finding"));
        assert!(names.contains(&"finish"));
    }

    #[test]
    fn initialize_returns_correct_protocol_version() {
        let result = handle_initialize(&json!({})).unwrap();
        assert_eq!(
            result["protocolVersion"].as_str().unwrap(),
            MCP_PROTOCOL_VERSION
        );
        assert_eq!(result["serverInfo"]["name"].as_str().unwrap(), "nevelio");
    }

    #[test]
    fn report_finding_accumulates() {
        let state = Arc::new(Mutex::new(McpState {
            target: None,
            accept_legal: true,
            timeout_secs: 30,
            findings: Vec::new(),
            client: reqwest::Client::new(),
        }));

        let args = json!({
            "title":       "SQLi dans /api/users",
            "severity":    "high",
            "endpoint":    "GET /api/users",
            "description": "Injection SQL détectée",
        });

        let r1 = tool_report_finding(&args, Arc::clone(&state));
        assert!(r1.is_ok());
        assert_eq!(state.lock().unwrap().findings.len(), 1);

        let r2 = tool_report_finding(&args, Arc::clone(&state));
        assert!(r2.is_ok());
        assert_eq!(state.lock().unwrap().findings.len(), 2);
    }

    #[test]
    fn finish_returns_all_findings() {
        let state = Arc::new(Mutex::new(McpState {
            target: None,
            accept_legal: true,
            timeout_secs: 30,
            findings: vec![
                json!({"title": "A", "severity": "high", "endpoint": "/a", "description": "x", "recommendation": "", "proof": ""}),
                json!({"title": "B", "severity": "low",  "endpoint": "/b", "description": "y", "recommendation": "", "proof": ""}),
            ],
            client: reqwest::Client::new(),
        }));

        let result = tool_finish(&json!({"summary": "Done"}), state).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("2 findings"));
        assert!(text.contains("Done"));
    }

    #[test]
    fn probe_endpoint_requires_accept_legal() {
        let state = Arc::new(Mutex::new(McpState {
            target: None,
            accept_legal: false, // ← not accepted
            timeout_secs: 30,
            findings: Vec::new(),
            client: reqwest::Client::new(),
        }));

        // probe_endpoint is async but the legal check is sync — test with tokio::test
        // We verify the error path using the future returned
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(tool_probe_endpoint(
            &json!({"url": "http://localhost:9999"}),
            state,
        ));
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32603);
    }

    #[test]
    fn unknown_tool_returns_error() {
        // tools/call with unknown name
        let rt = tokio::runtime::Runtime::new().unwrap();
        let state = Arc::new(Mutex::new(McpState {
            target: None,
            accept_legal: true,
            timeout_secs: 30,
            findings: Vec::new(),
            client: reqwest::Client::new(),
        }));
        let result = rt.block_on(handle_tools_call(
            &json!({"name": "nonexistent_tool", "arguments": {}}),
            state,
        ));
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, -32602);
    }
}
