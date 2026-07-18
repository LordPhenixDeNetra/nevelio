/// OpenAI-compatible provider — handles OpenAI, Mistral, and Groq (same API shape).
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use super::{AiProvider, CompletionOpts, Message, ToolCall, ToolCallResponse, ToolDefinition};

pub struct OpenAiProvider {
    provider_name: String,
    api_key: String,
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f32,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(
        provider_name: &str,
        api_key: String,
        base_url: String,
        model: String,
        max_tokens: u32,
        temperature: f32,
    ) -> Self {
        Self {
            provider_name: provider_name.to_string(),
            api_key,
            base_url,
            model,
            max_tokens,
            temperature,
            client: reqwest::Client::new(),
        }
    }

    /// Returns `CompletionOpts` pre-populated from provider config defaults.
    pub fn default_opts(&self) -> CompletionOpts {
        CompletionOpts {
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            model: None,
        }
    }

    fn resolve_model<'a>(&'a self, opts: &'a CompletionOpts) -> &'a str {
        opts.model.as_deref().unwrap_or(&self.model)
    }

    fn chat_url(&self) -> String {
        format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        )
    }

    fn to_api_messages(messages: &[Message]) -> Vec<Value> {
        messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    super::Role::System => "system",
                    super::Role::User => "user",
                    super::Role::Assistant => "assistant",
                };
                json!({ "role": role, "content": m.content })
            })
            .collect()
    }

    async fn post(&self, body: Value) -> Result<Value> {
        let resp = self
            .client
            .post(self.chat_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Requête échouée")?;

        let status = resp.status();
        let bytes = resp.bytes().await.context("Lecture réponse")?;

        if !status.is_success() {
            let err: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
            anyhow::bail!(
                "{} API erreur {} : {}",
                self.provider_name,
                status,
                err.pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
            );
        }

        serde_json::from_slice(&bytes).context("Parsing réponse")
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }
    fn model(&self) -> &str {
        &self.model
    }

    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String> {
        let body = json!({
            "model":       self.resolve_model(opts),
            "max_tokens":  opts.max_tokens,
            "temperature": opts.temperature,
            "messages":    Self::to_api_messages(messages),
        });

        let resp = self.post(body).await?;
        resp.pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Champ 'choices[0].message.content' manquant"))
    }

    async fn complete_json(
        &self,
        messages: &[Message],
        _schema: Value,
        opts: &CompletionOpts,
    ) -> Result<Value> {
        let body = json!({
            "model":           self.resolve_model(opts),
            "max_tokens":      opts.max_tokens,
            "temperature":     opts.temperature,
            "messages":        Self::to_api_messages(messages),
            "response_format": { "type": "json_object" },
        });

        let resp = self.post(body).await?;
        let text = resp
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Contenu vide dans réponse"))?;

        serde_json::from_str(text).context("Parsing JSON réponse")
    }

    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        opts: &CompletionOpts,
    ) -> Result<ToolCallResponse> {
        let api_tools: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name":        t.name,
                        "description": t.description,
                        "parameters":  t.parameters,
                    }
                })
            })
            .collect();

        let body = json!({
            "model":       self.resolve_model(opts),
            "max_tokens":  opts.max_tokens,
            "temperature": opts.temperature,
            "messages":    Self::to_api_messages(messages),
            "tools":       api_tools,
        });

        let resp = self.post(body).await?;
        let choice = &resp["choices"][0]["message"];

        let text = choice["content"].as_str().map(|s| s.to_string());

        let tool_calls = choice["tool_calls"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|tc| {
                let id = tc["id"].as_str().map(|s| s.to_string());
                let name = tc["function"]["name"].as_str()?;
                let args_str = tc["function"]["arguments"].as_str().unwrap_or("{}");
                let arguments = serde_json::from_str(args_str).unwrap_or(json!({}));
                Some(ToolCall {
                    id,
                    tool_name: name.to_string(),
                    arguments,
                })
            })
            .collect();

        Ok(ToolCallResponse { text, tool_calls })
    }
}
