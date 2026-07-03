/// Ollama local provider — uses the /api/chat endpoint.
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use super::{AiProvider, CompletionOpts, Message, ToolCall, ToolCallResponse, ToolDefinition};

pub struct OllamaProvider {
    base_url:    String,
    model:       String,
    max_tokens:  u32,
    temperature: f32,
    client:      reqwest::Client,
}

impl OllamaProvider {
    pub fn new(base_url: String, model: String, max_tokens: u32, temperature: f32) -> Self {
        Self { base_url, model, max_tokens, temperature, client: reqwest::Client::new() }
    }

    /// Returns `CompletionOpts` pre-populated from provider config defaults.
    pub fn default_opts(&self) -> CompletionOpts {
        CompletionOpts {
            max_tokens:  self.max_tokens,
            temperature: self.temperature,
            model:       None,
        }
    }

    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.base_url.trim_end_matches('/'))
    }

    fn resolve_model<'a>(&'a self, opts: &'a CompletionOpts) -> &'a str {
        opts.model.as_deref().unwrap_or(&self.model)
    }

    fn to_api_messages(messages: &[Message]) -> Vec<Value> {
        messages.iter().map(|m| {
            let role = match m.role {
                super::Role::System    => "system",
                super::Role::User      => "user",
                super::Role::Assistant => "assistant",
            };
            json!({ "role": role, "content": m.content })
        }).collect()
    }

    async fn post(&self, body: Value) -> Result<Value> {
        let resp = self.client
            .post(self.chat_url())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Connexion à Ollama échouée — est-ce qu'Ollama est lancé ?")?;

        let status = resp.status();
        let bytes  = resp.bytes().await.context("Lecture réponse Ollama")?;

        if !status.is_success() {
            let err: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
            anyhow::bail!(
                "Ollama erreur {} : {}",
                status,
                err["error"].as_str().unwrap_or("?")
            );
        }

        serde_json::from_slice(&bytes).context("Parsing réponse Ollama")
    }
}

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self)  -> &str { "ollama" }
    fn model(&self) -> &str { &self.model }

    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String> {
        let body = json!({
            "model":    self.resolve_model(opts),
            "stream":   false,
            "options":  { "num_predict": opts.max_tokens, "temperature": opts.temperature },
            "messages": Self::to_api_messages(messages),
        });

        let resp = self.post(body).await?;
        resp.pointer("/message/content")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Champ 'message.content' manquant dans réponse Ollama"))
    }

    async fn complete_json(
        &self,
        messages: &[Message],
        _schema:  Value,
        opts:     &CompletionOpts,
    ) -> Result<Value> {
        let body = json!({
            "model":    self.resolve_model(opts),
            "stream":   false,
            "format":   "json",
            "options":  { "num_predict": opts.max_tokens, "temperature": opts.temperature },
            "messages": Self::to_api_messages(messages),
        });

        let resp = self.post(body).await?;
        let text = resp.pointer("/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Contenu vide dans réponse Ollama"))?;

        serde_json::from_str(text).context("Parsing JSON réponse Ollama")
    }

    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools:    &[ToolDefinition],
        opts:     &CompletionOpts,
    ) -> Result<ToolCallResponse> {
        // Ollama tool_calls format (supported in llama3.1+, mistral, etc.)
        let api_tools: Vec<Value> = tools.iter().map(|t| json!({
            "type": "function",
            "function": {
                "name":        t.name,
                "description": t.description,
                "parameters":  t.parameters,
            }
        })).collect();

        let body = json!({
            "model":    self.resolve_model(opts),
            "stream":   false,
            "options":  { "num_predict": opts.max_tokens, "temperature": opts.temperature },
            "messages": Self::to_api_messages(messages),
            "tools":    api_tools,
        });

        let resp  = self.post(body).await?;
        let msg   = &resp["message"];
        let text  = msg["content"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string());

        let tool_calls = msg["tool_calls"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|tc| {
                let name      = tc["function"]["name"].as_str()?;
                let arguments = tc["function"]["arguments"].clone();
                Some(ToolCall { id: None, tool_name: name.to_string(), arguments })
            })
            .collect();

        Ok(ToolCallResponse { text, tool_calls })
    }
}
