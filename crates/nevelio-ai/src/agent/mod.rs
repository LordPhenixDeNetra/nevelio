mod guardrail;
mod tools;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::provider::{AiProvider, CompletionOpts, Message, ToolCall};

pub use guardrail::Guardrail;
pub use tools::nevelio_tools;

// ── Config ────────────────────────────────────────────────────────────────────

pub struct AgentConfig {
    pub target:         String,
    pub max_iterations: u32,
    pub max_requests:   u32,
    pub ai_budget:      Option<u32>,
    pub dry_run:        bool,
    pub lang:           String,
}

// ── Output ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFinding {
    pub id:             String,
    pub title:          String,
    pub severity:       String,
    pub endpoint:       String,
    pub method:         String,
    pub description:    String,
    pub recommendation: String,
    pub proof:          String,
}

#[derive(Debug)]
pub struct AgentResult {
    pub findings:      Vec<AgentFinding>,
    pub iterations:    u32,
    pub requests_made: u32,
    pub tokens_spent:  u32,
    pub summary:       String,
}

// ── Internal state ────────────────────────────────────────────────────────────

struct AgentState {
    findings:  Vec<AgentFinding>,
    finished:  bool,
    summary:   String,
    guardrail: Guardrail,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the autonomous agent loop.
///
/// The LLM drives the loop via tool calls. Guardrails enforce scope, request
/// count, and token budget hard limits server-side (not relying on the LLM).
pub async fn run_agent(
    config:    &AgentConfig,
    endpoints: &[String],
    provider:  &dyn AiProvider,
    opts:      &CompletionOpts,
) -> Result<AgentResult> {
    let mut state = AgentState {
        findings:  Vec::new(),
        finished:  false,
        summary:   String::new(),
        guardrail: Guardrail::new(
            &config.target,
            config.max_requests,
            config.ai_budget,
            config.dry_run,
        ),
    };

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Nevelio-Agent/0.1 (security research)")
        .danger_accept_invalid_certs(false)
        .build()?;

    let tools = nevelio_tools();
    let mut messages = vec![
        Message::system(&build_system_prompt(config)),
        Message::user(&build_initial_message(config, endpoints)),
    ];

    let mut iterations = 0u32;

    for _ in 1..=config.max_iterations {
        iterations += 1;

        // Token budget check (rough estimate: 1 token ≈ 4 chars)
        if config.ai_budget.is_some() {
            let char_sum: usize = messages.iter().map(|m| m.content.len()).sum();
            let estimated = (char_sum / 4) as u32;
            if let Err(e) = state.guardrail.check_budget(estimated) {
                state.summary = e.to_string();
                break;
            }
            state.guardrail.record_tokens(estimated);
        }

        let response = provider
            .complete_with_tools(&messages, &tools, opts)
            .await?;

        let assistant_text = response.text.unwrap_or_default();

        // Add assistant turn to conversation history
        let turn_text = if assistant_text.is_empty() && !response.tool_calls.is_empty() {
            format!("[Calling {} tool(s)]", response.tool_calls.len())
        } else {
            assistant_text.clone()
        };
        messages.push(Message::assistant(&turn_text));

        // If the LLM stopped without any tool call, the agent is done
        if response.tool_calls.is_empty() {
            state.summary = assistant_text;
            break;
        }

        // Execute tool calls, collect results
        let mut result_parts = Vec::new();
        for tool_call in &response.tool_calls {
            let result = execute_tool_call(
                tool_call,
                &mut state,
                endpoints,
                &http_client,
                config,
            )
            .await;

            let result_str = match result {
                Ok(r)  => r,
                Err(e) => {
                    let msg = e.to_string().replace('"', "'");
                    format!("{{\"error\": \"{}\"}}", msg)
                }
            };

            result_parts.push(format!(
                "[Tool: {}]\n{}",
                tool_call.tool_name, result_str
            ));

            if state.finished {
                break;
            }
        }

        // Feed results back to the model
        messages.push(Message::user(result_parts.join("\n\n")));

        if state.finished {
            break;
        }
    }

    let requests_made = state.guardrail.requests_made();
    let tokens_spent  = state.guardrail.tokens_spent();

    Ok(AgentResult {
        findings: state.findings,
        iterations,
        requests_made,
        tokens_spent,
        summary: state.summary,
    })
}

// ── Tool dispatch ─────────────────────────────────────────────────────────────

async fn execute_tool_call(
    tool_call:   &ToolCall,
    state:       &mut AgentState,
    endpoints:   &[String],
    http_client: &reqwest::Client,
    config:      &AgentConfig,
) -> Result<String> {
    match tool_call.tool_name.as_str() {
        "list_endpoints" => {
            Ok(serde_json::json!({
                "count":     endpoints.len(),
                "endpoints": endpoints
            })
            .to_string())
        }

        "probe_endpoint" => {
            execute_probe(tool_call, state, http_client, config).await
        }

        "report_finding" => {
            let id      = format!("agent-{:03}", state.findings.len() + 1);
            let finding = AgentFinding {
                id:             id.clone(),
                title:          get_str(&tool_call.arguments, "title"),
                severity:       get_str(&tool_call.arguments, "severity"),
                endpoint:       get_str(&tool_call.arguments, "endpoint"),
                method:         get_str(&tool_call.arguments, "method"),
                description:    get_str(&tool_call.arguments, "description"),
                recommendation: get_str(&tool_call.arguments, "recommendation"),
                proof:          get_str(&tool_call.arguments, "proof"),
            };
            state.findings.push(finding);
            Ok(serde_json::json!({ "id": id, "recorded": true }).to_string())
        }

        "finish" => {
            state.finished = true;
            state.summary  = get_str(&tool_call.arguments, "summary");
            Ok(serde_json::json!({ "status": "done" }).to_string())
        }

        _ => anyhow::bail!("Unknown tool: {}", tool_call.tool_name),
    }
}

// ── probe_endpoint implementation ─────────────────────────────────────────────

async fn execute_probe(
    tool_call:   &ToolCall,
    state:       &mut AgentState,
    http_client: &reqwest::Client,
    config:      &AgentConfig,
) -> Result<String> {
    let method = get_str(&tool_call.arguments, "method").to_uppercase();
    let url    = get_str(&tool_call.arguments, "url");

    if url.is_empty() {
        anyhow::bail!("probe_endpoint: 'url' is required");
    }

    // G.5 — scope guardrail
    state.guardrail.check_scope(&url)?;
    // G.6 — request count guardrail
    state.guardrail.check_requests()?;

    // G.8 — dry-run mode
    if config.dry_run {
        state.guardrail.record_request();
        return Ok(serde_json::json!({
            "dry_run": true,
            "method":  method,
            "url":     url,
            "status":  200,
            "body":    "[dry-run: request not sent]"
        })
        .to_string());
    }

    // Build request
    let rb = match method.as_str() {
        "GET"     => http_client.get(&url),
        "POST"    => http_client.post(&url),
        "PUT"     => http_client.put(&url),
        "PATCH"   => http_client.patch(&url),
        "DELETE"  => http_client.delete(&url),
        "HEAD"    => http_client.head(&url),
        "OPTIONS" => http_client.request(reqwest::Method::OPTIONS, &url),
        _         => http_client.get(&url),
    };

    // Custom headers
    let rb = if let Some(hdrs) = tool_call.arguments.get("headers").and_then(|v| v.as_object()) {
        let mut rb = rb;
        for (k, v) in hdrs {
            if let Some(v_str) = v.as_str() {
                rb = rb.header(k.as_str(), v_str);
            }
        }
        rb
    } else {
        rb
    };

    // Body
    let rb = if let Some(body) = tool_call.arguments.get("body").and_then(|v| v.as_str()) {
        rb.body(body.to_string())
    } else {
        rb
    };

    state.guardrail.record_request();
    let t0 = std::time::Instant::now();

    let resp = rb.send().await.map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    let latency_ms = t0.elapsed().as_millis() as u64;
    let status     = resp.status().as_u16();

    // Capture security-relevant response headers
    let sec_headers: Vec<String> = resp
        .headers()
        .iter()
        .filter(|(k, _)| {
            matches!(
                k.as_str(),
                "content-type"
                    | "server"
                    | "x-powered-by"
                    | "set-cookie"
                    | "access-control-allow-origin"
                    | "www-authenticate"
                    | "x-frame-options"
                    | "strict-transport-security"
                    | "content-security-policy"
                    | "x-content-type-options"
            )
        })
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("?")))
        .collect();

    let body = resp.text().await.unwrap_or_default();
    let body_snippet = if body.len() > 1500 {
        format!("{}…[+{} chars truncated]", &body[..1500], body.len() - 1500)
    } else {
        body
    };

    Ok(serde_json::json!({
        "status":     status,
        "latency_ms": latency_ms,
        "headers":    sec_headers,
        "body":       body_snippet
    })
    .to_string())
}

// ── Prompt builders ───────────────────────────────────────────────────────────

fn build_system_prompt(config: &AgentConfig) -> String {
    let lang_instr = match config.lang.as_str() {
        "en" => "Respond in English.",
        "es" => "Responde en español.",
        _    => "Réponds en français.",
    };

    format!(
        r#"You are a professional API penetration tester conducting an authorized security assessment.

Target: {target}

Your mission:
1. Explore the API attack surface using the tools available to you
2. Test for OWASP API Top 10 vulnerabilities:
   - Broken Object Level Authorization (BOLA/IDOR)
   - Broken Authentication — missing/weak JWT, session fixation
   - Excessive Data Exposure — sensitive fields leaked in responses
   - Lack of Rate Limiting — brute-force, enumeration
   - Broken Function Level Authorization — accessing admin endpoints
   - Mass Assignment — sending unexpected fields
   - Security Misconfiguration — verbose errors, default credentials
   - Injection — SQLi, NoSQLi, XSS payloads in parameters
   - SSRF — server-side request forgery via URL parameters
3. Report only confirmed, exploitable issues backed by evidence

Constraints (enforced server-side — violations are automatically rejected):
- Only request URLs under: {target}
- Max {max_req} HTTP requests total
- Max {max_iter} reasoning iterations

Workflow:
1. Call `list_endpoints` to see the pre-discovered endpoints
2. Probe each endpoint: normal request → missing auth → IDOR → injection → header manipulation
3. When you find something suspicious, probe further to confirm before reporting
4. Call `report_finding` for each confirmed vulnerability
5. Call `finish` with a summary when testing is complete

{lang_instr}"#,
        target   = config.target,
        max_req  = config.max_requests,
        max_iter = config.max_iterations,
        lang_instr = lang_instr,
    )
}

fn build_initial_message(config: &AgentConfig, endpoints: &[String]) -> String {
    let ep_note = if endpoints.is_empty() {
        "No endpoints were pre-discovered. Start by calling list_endpoints, then probe the target root directly.".to_string()
    } else {
        format!(
            "{} endpoint(s) were pre-discovered. Call list_endpoints to see them, then begin your assessment.",
            endpoints.len()
        )
    };

    format!("Start the security assessment of: {}\n\n{}", config.target, ep_note)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_str(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}
