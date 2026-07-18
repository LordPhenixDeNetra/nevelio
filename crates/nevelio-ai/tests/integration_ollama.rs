/// Integration tests for OllamaProvider.
///
/// These tests are SKIPPED unless the `OLLAMA_HOST` environment variable is set.
/// They are intended for local development and CI environments with a running
/// Ollama instance — never gated on real API keys, so they run for free.
///
/// Run locally:
///   OLLAMA_HOST=http://localhost:11434 cargo test --package nevelio-ai --test integration_ollama
///
/// Skip in CI (default): these tests are excluded from the main CI job.
/// A dedicated CI job gated on `OLLAMA_HOST` is optional.

#[cfg(test)]
mod ollama_integration {
    use nevelio_ai::provider::{
        ollama::OllamaProvider, AiProvider, CompletionOpts, Message, ToolDefinition,
    };
    use serde_json::json;

    fn ollama_base_url() -> Option<String> {
        std::env::var("OLLAMA_HOST").ok()
    }

    fn default_model() -> String {
        std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.2".to_string())
    }

    fn skip_if_no_ollama() -> Option<OllamaProvider> {
        let url = ollama_base_url()?;
        Some(OllamaProvider::new(url, default_model(), 256, 0.2))
    }

    // ── complete ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ollama_complete_basic() {
        let Some(provider) = skip_if_no_ollama() else {
            eprintln!("SKIP: OLLAMA_HOST not set");
            return;
        };

        let msgs = vec![Message::user("Reply with just the number 42.")];
        let opts = CompletionOpts {
            max_tokens: 64,
            temperature: 0.0,
            model: None,
        };

        let reply = provider
            .complete(&msgs, &opts)
            .await
            .expect("OllamaProvider::complete should succeed");

        assert!(!reply.is_empty(), "Response should not be empty");
        eprintln!("Ollama reply: {:?}", reply);
    }

    // ── complete_json ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ollama_complete_json() {
        let Some(provider) = skip_if_no_ollama() else {
            eprintln!("SKIP: OLLAMA_HOST not set");
            return;
        };

        let msgs = vec![Message::user(
            r#"Return a JSON object with a single field "status" set to "ok"."#,
        )];
        let schema = json!({ "type": "object", "properties": { "status": { "type": "string" } } });
        let opts = CompletionOpts {
            max_tokens: 128,
            temperature: 0.0,
            model: None,
        };

        let value = provider
            .complete_json(&msgs, schema, &opts)
            .await
            .expect("OllamaProvider::complete_json should succeed");

        assert!(value.is_object(), "Expected JSON object, got: {:?}", value);
        eprintln!("Ollama JSON reply: {:?}", value);
    }

    // ── complete_with_tools ────────────────────────────────────────────────────
    // Note: tool_call support requires a model that supports it (llama3.1+, mixtral, etc.)

    #[tokio::test]
    async fn test_ollama_complete_with_tools() {
        let Some(provider) = skip_if_no_ollama() else {
            eprintln!("SKIP: OLLAMA_HOST not set");
            return;
        };

        // Only run if the model is known to support tools
        let model = default_model();
        let supports_tools = model.starts_with("llama3.1")
            || model.starts_with("llama3.2")
            || model.starts_with("mixtral");

        if !supports_tools {
            eprintln!("SKIP: model '{}' may not support tool calls", model);
            return;
        }

        let msgs = vec![
            Message::system("You are a helpful assistant."),
            Message::user("What is the weather in Paris? Use the get_weather tool."),
        ];
        let tools = vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: "Get current weather for a city.".to_string(),
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
            .expect("OllamaProvider::complete_with_tools should succeed");

        eprintln!("Tool calls: {:?}", resp.tool_calls);
        // We don't assert on tool_calls count since not all models use them reliably
        // — the test validates that the call doesn't panic or error
    }

    // ── connectivity check ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ollama_unreachable_gives_error() {
        // No OLLAMA_HOST check — tests a hardcoded unreachable port
        let provider = OllamaProvider::new(
            "http://localhost:59999".to_string(), // nothing listening here
            "llama3.2".to_string(),
            64,
            0.0,
        );

        let msgs = vec![Message::user("hello")];
        let opts = CompletionOpts::default();

        let result = provider.complete(&msgs, &opts).await;
        assert!(result.is_err(), "Expected error for unreachable Ollama");
        eprintln!("Expected error: {:?}", result.unwrap_err());
    }
}
