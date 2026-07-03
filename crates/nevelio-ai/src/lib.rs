pub mod agent;
pub mod payloads;
pub mod provider;
pub mod remediation;
pub mod report;
pub mod triage;

rust_i18n::i18n!("locales", fallback = "fr");

pub use provider::{
    AiProvider, CompletionOpts, Message, Role,
    ToolCall, ToolCallResponse, ToolDefinition,
};
pub use provider::factory::{build_provider, build_named_provider};
pub use provider::router::{build_provider_for_task, TaskType};
pub use triage::FindingContext;
pub use agent::{AgentConfig, AgentFinding, AgentResult, run_agent};
pub use payloads::{generate as generate_payloads, merge_with_static, PayloadContext, PayloadSet, VulnType};

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;

    // ── MockProvider ──────────────────────────────────────────────────────────

    struct MockProvider {
        reply: String,
    }

    #[async_trait]
    impl AiProvider for MockProvider {
        fn name(&self)  -> &str { "mock" }
        fn model(&self) -> &str { "mock-model" }

        async fn complete(&self, _messages: &[Message], _opts: &CompletionOpts) -> Result<String> {
            Ok(self.reply.clone())
        }

        async fn complete_json(
            &self,
            _messages: &[Message],
            _schema:   serde_json::Value,
            _opts:     &CompletionOpts,
        ) -> Result<serde_json::Value> {
            serde_json::from_str(&self.reply).map_err(Into::into)
        }

        async fn complete_with_tools(
            &self,
            _messages: &[Message],
            tools:    &[ToolDefinition],
            _opts:     &CompletionOpts,
        ) -> Result<ToolCallResponse> {
            Ok(ToolCallResponse {
                text:       Some(self.reply.clone()),
                tool_calls: tools.iter().map(|t| ToolCall {
                    id:        None,
                    tool_name: t.name.clone(),
                    arguments: serde_json::json!({}),
                }).collect(),
            })
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mock_complete_returns_reply() {
        let provider = MockProvider { reply: "bonjour".to_string() };
        let msgs  = vec![Message::user("hello")];
        let opts  = CompletionOpts::default();
        let reply = provider.complete(&msgs, &opts).await.unwrap();
        assert_eq!(reply, "bonjour");
    }

    #[tokio::test]
    async fn mock_complete_json_parses_object() {
        let provider = MockProvider { reply: r#"{"ok":true}"#.to_string() };
        let msgs   = vec![Message::user("give json")];
        let schema = serde_json::json!({});
        let opts   = CompletionOpts::default();
        let value  = provider.complete_json(&msgs, schema, &opts).await.unwrap();
        assert_eq!(value["ok"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn mock_with_tools_returns_tool_calls() {
        let provider = MockProvider { reply: "done".to_string() };
        let msgs  = vec![Message::user("use tool")];
        let tools = vec![ToolDefinition {
            name:        "scan_endpoint".to_string(),
            description: "Scan an API endpoint".to_string(),
            parameters:  serde_json::json!({}),
        }];
        let opts  = CompletionOpts::default();
        let resp  = provider.complete_with_tools(&msgs, &tools, &opts).await.unwrap();
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].tool_name, "scan_endpoint");
    }

    #[test]
    fn message_constructors_set_roles() {
        assert_eq!(Message::system("s").role, Role::System);
        assert_eq!(Message::user("u").role,   Role::User);
        assert_eq!(Message::assistant("a").role, Role::Assistant);
    }

    #[test]
    fn completion_opts_default() {
        let opts = CompletionOpts::default();
        assert_eq!(opts.max_tokens, 4096);
        assert!(opts.model.is_none());
    }
}
