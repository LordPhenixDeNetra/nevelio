use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{AiProvider, CompletionOpts, Message, Role, ToolCall, ToolCallResponse, ToolDefinition};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    api_key:     String,
    model:       String,
    max_tokens:  u32,
    temperature: f32,
    client:      reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(api_key: String, model: String, max_tokens: u32, temperature: f32) -> Self {
        Self {
            api_key,
            model,
            max_tokens,
            temperature,
            client: reqwest::Client::new(),
        }
    }

    /// Returns `CompletionOpts` pre-populated from provider config defaults.
    pub fn default_opts(&self) -> CompletionOpts {
        CompletionOpts {
            max_tokens:  self.max_tokens,
            temperature: self.temperature,
            model:       None,
        }
    }

    fn resolve_model<'a>(&'a self, opts: &'a CompletionOpts) -> &'a str {
        opts.model.as_deref().unwrap_or(&self.model)
    }

    async fn post(&self, body: Value) -> Result<Value> {
        let resp = self.client
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Requête Anthropic échouée")?;

        let status = resp.status();
        let bytes  = resp.bytes().await.context("Lecture réponse Anthropic")?;

        if !status.is_success() {
            let err: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
            anyhow::bail!(
                "Anthropic API erreur {} : {}",
                status,
                err.get("error").and_then(|e| e.get("message")).and_then(Value::as_str).unwrap_or("?")
            );
        }

        serde_json::from_slice(&bytes).context("Parsing réponse Anthropic")
    }

    fn build_body(&self, messages: &[Message], opts: &CompletionOpts, extra: Value) -> Value {
        let (system, chat) = split_system(messages);

        let mut body = json!({
            "model":       self.resolve_model(opts),
            "max_tokens":  opts.max_tokens,
            "temperature": opts.temperature,
            "messages":    chat,
        });

        if let Some(sys) = system {
            body["system"] = Value::String(sys);
        }

        // Merge extra fields (e.g. tools)
        if let Value::Object(extra_map) = extra {
            if let Value::Object(ref mut map) = body {
                map.extend(extra_map);
            }
        }

        body
    }
}

#[async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &str { "anthropic" }
    fn model(&self) -> &str { &self.model }

    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String> {
        let body = self.build_body(messages, opts, json!({}));
        let resp = self.post(body).await?;
        extract_text(&resp)
    }

    async fn complete_json(
        &self,
        messages: &[Message],
        _schema:  Value,
        opts:     &CompletionOpts,
    ) -> Result<Value> {
        // Instruct the model to respond in JSON
        let mut msgs = messages.to_vec();
        msgs.push(Message::user(
            "Réponds UNIQUEMENT avec un objet JSON valide, sans texte avant ou après.",
        ));

        let body = self.build_body(&msgs, opts, json!({}));
        let resp = self.post(body).await?;
        let text = extract_text(&resp)?;

        // Strip optional markdown fences
        let clean = text.trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        serde_json::from_str(clean).context("Parsing JSON réponse Anthropic")
    }

    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools:    &[ToolDefinition],
        opts:     &CompletionOpts,
    ) -> Result<ToolCallResponse> {
        let api_tools: Vec<Value> = tools.iter().map(|t| json!({
            "name":        t.name,
            "description": t.description,
            "input_schema": t.parameters,
        })).collect();

        let body = self.build_body(messages, opts, json!({ "tools": api_tools }));
        let resp = self.post(body).await?;

        parse_tool_response(&resp)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn split_system(messages: &[Message]) -> (Option<String>, Vec<Value>) {
    let mut system = None;
    let chat: Vec<Value> = messages.iter().filter_map(|m| {
        match m.role {
            Role::System => { system = Some(m.content.clone()); None }
            Role::User      => Some(json!({ "role": "user",      "content": m.content })),
            Role::Assistant => Some(json!({ "role": "assistant",  "content": m.content })),
        }
    }).collect();
    (system, chat)
}

fn extract_text(resp: &Value) -> Result<String> {
    resp["content"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|c| c["text"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Champ 'content[0].text' manquant dans réponse Anthropic"))
}

fn parse_tool_response(resp: &Value) -> Result<ToolCallResponse> {
    let mut text       = None;
    let mut tool_calls = Vec::new();

    if let Some(content) = resp["content"].as_array() {
        for block in content {
            match block["type"].as_str() {
                Some("text") => {
                    text = block["text"].as_str().map(|s| s.to_string());
                }
                Some("tool_use") => {
                    #[derive(Deserialize)]
                    struct ToolUse { id: Option<String>, name: String, input: Value }
                    if let Ok(tu) = serde_json::from_value::<ToolUse>(block.clone()) {
                        tool_calls.push(ToolCall {
                            id:        tu.id,
                            tool_name: tu.name,
                            arguments: tu.input,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    Ok(ToolCallResponse { text, tool_calls })
}
