use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ── Message types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
        }
    }
}

// ── Completion options ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompletionOpts {
    pub max_tokens: u32,
    pub temperature: f32,
    /// Override the provider's default model for this call
    pub model: Option<String>,
}

impl Default for CompletionOpts {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            temperature: 0.2,
            model: None,
        }
    }
}

// ── Tool types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema describing the input parameters
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: Option<String>,
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ToolCallResponse {
    /// Optional text content alongside tool calls
    pub text: Option<String>,
    pub tool_calls: Vec<ToolCall>,
}

// ── AiProvider trait ──────────────────────────────────────────────────────────

#[async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;

    /// Simple completion — returns the assistant text response.
    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String>;

    /// Completion that returns a parsed JSON value.
    /// The provider is instructed to respond with JSON matching `schema`.
    async fn complete_json(
        &self,
        messages: &[Message],
        schema: serde_json::Value,
        opts: &CompletionOpts,
    ) -> Result<serde_json::Value>;

    /// Completion with tool definitions — returns tool calls (and optional text).
    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        opts: &CompletionOpts,
    ) -> Result<ToolCallResponse>;
}

// ── Re-exports ────────────────────────────────────────────────────────────────
pub mod anthropic;
#[cfg(feature = "bedrock")]
pub mod bedrock;
pub mod factory;
pub mod fallback;
pub mod ollama;
pub mod openai;
pub mod router;
