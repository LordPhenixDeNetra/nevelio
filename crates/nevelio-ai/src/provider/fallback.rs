use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use super::{AiProvider, CompletionOpts, Message, ToolCallResponse, ToolDefinition};

// ── FallbackProvider (A.4) ────────────────────────────────────────────────────

/// Wraps a primary and a secondary provider.
///
/// Every `AiProvider` method tries the primary first; on any error, it logs the
/// switch and delegates to the fallback. Max 2 attempts total (primary → fallback).
pub struct FallbackProvider {
    primary: Box<dyn AiProvider>,
    fallback: Box<dyn AiProvider>,
}

impl FallbackProvider {
    pub fn new(primary: Box<dyn AiProvider>, fallback: Box<dyn AiProvider>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl AiProvider for FallbackProvider {
    fn name(&self) -> &str {
        self.primary.name()
    }
    fn model(&self) -> &str {
        self.primary.model()
    }

    async fn complete(&self, messages: &[Message], opts: &CompletionOpts) -> Result<String> {
        match self.primary.complete(messages, opts).await {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::warn!(
                    "Provider '{}' échoué (complete): {} — basculement vers '{}'",
                    self.primary.name(),
                    e,
                    self.fallback.name()
                );
                self.fallback.complete(messages, opts).await
            }
        }
    }

    async fn complete_json(
        &self,
        messages: &[Message],
        schema: Value,
        opts: &CompletionOpts,
    ) -> Result<Value> {
        match self
            .primary
            .complete_json(messages, schema.clone(), opts)
            .await
        {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::warn!(
                    "Provider '{}' échoué (complete_json): {} — basculement vers '{}'",
                    self.primary.name(),
                    e,
                    self.fallback.name()
                );
                self.fallback.complete_json(messages, schema, opts).await
            }
        }
    }

    async fn complete_with_tools(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        opts: &CompletionOpts,
    ) -> Result<ToolCallResponse> {
        match self
            .primary
            .complete_with_tools(messages, tools, opts)
            .await
        {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::warn!(
                    "Provider '{}' échoué (complete_with_tools): {} — basculement vers '{}'",
                    self.primary.name(),
                    e,
                    self.fallback.name()
                );
                self.fallback
                    .complete_with_tools(messages, tools, opts)
                    .await
            }
        }
    }
}
