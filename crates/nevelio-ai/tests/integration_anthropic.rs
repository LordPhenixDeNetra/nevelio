/// Integration tests for AnthropicProvider.
///
/// These tests ONLY run when both of the following env vars are set:
///   - `ANTHROPIC_API_KEY` — valid Anthropic API key
///   - `RUN_AI_INTEGRATION_TESTS=1` — explicit opt-in guard (prevents accidental billing)
///
/// Run locally:
///   ANTHROPIC_API_KEY=sk-ant-... RUN_AI_INTEGRATION_TESTS=1 \
///     cargo test --package nevelio-ai --test integration_anthropic
///
/// These tests are intentionally excluded from default CI to avoid API costs.

#[cfg(test)]
mod anthropic_integration {
    use nevelio_ai::provider::{
        anthropic::AnthropicProvider, AiProvider, CompletionOpts, Message, ToolDefinition,
    };
    use serde_json::json;

    fn should_run() -> bool {
        std::env::var("ANTHROPIC_API_KEY").is_ok()
            && std::env::var("RUN_AI_INTEGRATION_TESTS").as_deref() == Ok("1")
    }

    fn build_provider() -> AnthropicProvider {
        let key = std::env::var("ANTHROPIC_API_KEY").unwrap();
        let model = std::env::var("ANTHROPIC_MODEL")
            .unwrap_or_else(|_| "claude-haiku-4-5-20251001".to_string());
        // Use the cheapest model by default to minimise test cost
        AnthropicProvider::new(key, model, 128, 0.0)
    }

    // ── complete ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anthropic_complete_basic() {
        if !should_run() {
            eprintln!("SKIP: ANTHROPIC_API_KEY or RUN_AI_INTEGRATION_TESTS=1 not set");
            return;
        }

        let provider = build_provider();
        let msgs = vec![
            Message::system("Reply with a single word only."),
            Message::user("What is 1 + 1?"),
        ];
        let opts = CompletionOpts {
            max_tokens: 32,
            temperature: 0.0,
            model: None,
        };

        let reply = provider
            .complete(&msgs, &opts)
            .await
            .expect("AnthropicProvider::complete should succeed");

        assert!(!reply.is_empty(), "Response should not be empty");
        eprintln!("Anthropic reply: {:?}", reply);
    }

    // ── complete_json ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anthropic_complete_json() {
        if !should_run() {
            eprintln!("SKIP: ANTHROPIC_API_KEY or RUN_AI_INTEGRATION_TESTS=1 not set");
            return;
        }

        let provider = build_provider();
        let msgs = vec![Message::user(r#"Return JSON: {"result": 42}"#)];
        let schema = json!({
            "type": "object",
            "properties": { "result": { "type": "number" } },
            "required": ["result"]
        });
        let opts = CompletionOpts {
            max_tokens: 64,
            temperature: 0.0,
            model: None,
        };

        let value = provider
            .complete_json(&msgs, schema, &opts)
            .await
            .expect("AnthropicProvider::complete_json should succeed");

        assert!(
            value["result"].is_number(),
            "Expected numeric 'result' field"
        );
        eprintln!("Anthropic JSON reply: {:?}", value);
    }

    // ── complete_with_tools ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anthropic_complete_with_tools() {
        if !should_run() {
            eprintln!("SKIP: ANTHROPIC_API_KEY or RUN_AI_INTEGRATION_TESTS=1 not set");
            return;
        }

        let provider = build_provider();
        let msgs = vec![
            Message::system("You are a helpful assistant. Always use the provided tool."),
            Message::user("Get the weather in Paris."),
        ];
        let tools = vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: "Get the current weather for a city.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string", "description": "City name" }
                },
                "required": ["city"]
            }),
        }];
        let opts = CompletionOpts {
            max_tokens: 256,
            temperature: 0.0,
            model: None,
        };

        let resp = provider
            .complete_with_tools(&msgs, &tools, &opts)
            .await
            .expect("AnthropicProvider::complete_with_tools should succeed");

        assert!(
            !resp.tool_calls.is_empty(),
            "Expected at least one tool call"
        );
        assert_eq!(resp.tool_calls[0].tool_name, "get_weather");
        assert!(
            resp.tool_calls[0].arguments.get("city").is_some(),
            "Expected 'city' argument"
        );
        eprintln!("Tool calls: {:?}", resp.tool_calls);
    }

    // ── bad key ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_anthropic_bad_key_gives_error() {
        // Runs unconditionally — uses an obviously invalid key, no billing
        let provider = AnthropicProvider::new(
            "sk-ant-invalid-key".to_string(),
            "claude-haiku-4-5-20251001".to_string(),
            32,
            0.0,
        );

        let msgs = vec![Message::user("hello")];
        let opts = CompletionOpts::default();
        let result = provider.complete(&msgs, &opts).await;

        assert!(result.is_err(), "Expected error for invalid API key");
        eprintln!("Expected auth error: {:?}", result.unwrap_err());
    }
}
