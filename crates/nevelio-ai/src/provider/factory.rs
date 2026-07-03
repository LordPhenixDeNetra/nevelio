use anyhow::{bail, Result};

use nevelio_config::AiConfig;

use super::{anthropic::AnthropicProvider, ollama::OllamaProvider, openai::OpenAiProvider, AiProvider};

/// Build the active provider from the resolved AI config.
pub fn build_provider(cfg: &AiConfig) -> Result<Box<dyn AiProvider>> {
    let name = cfg.active_provider_name();
    let prov_cfg = cfg
        .providers
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Provider '{}' introuvable dans la config", name))?;

    let api_key = prov_cfg
        .api_key_env
        .as_deref()
        .and_then(|env| std::env::var(env).ok());

    let base_url = prov_cfg.base_url.clone();
    let model    = prov_cfg.model.clone();
    let max_tokens  = prov_cfg.max_tokens.unwrap_or(4096);
    let temperature = prov_cfg.temperature.unwrap_or(0.2);

    match name {
        "anthropic" => {
            let key = api_key.ok_or_else(|| {
                let env = prov_cfg.api_key_env.as_deref().unwrap_or("ANTHROPIC_API_KEY");
                anyhow::anyhow!("Clé API Anthropic absente — définissez {}", env)
            })?;
            Ok(Box::new(AnthropicProvider::new(key, model, max_tokens, temperature)))
        }
        "openai" => {
            let key = api_key.ok_or_else(|| {
                let env = prov_cfg.api_key_env.as_deref().unwrap_or("OPENAI_API_KEY");
                anyhow::anyhow!("Clé API OpenAI absente — définissez {}", env)
            })?;
            Ok(Box::new(OpenAiProvider::new(
                "openai", key,
                base_url.unwrap_or_else(|| "https://api.openai.com".to_string()),
                model, max_tokens, temperature,
            )))
        }
        "mistral" => {
            let key = api_key.ok_or_else(|| {
                let env = prov_cfg.api_key_env.as_deref().unwrap_or("MISTRAL_API_KEY");
                anyhow::anyhow!("Clé API Mistral absente — définissez {}", env)
            })?;
            Ok(Box::new(OpenAiProvider::new(
                "mistral", key,
                base_url.unwrap_or_else(|| "https://api.mistral.ai".to_string()),
                model, max_tokens, temperature,
            )))
        }
        "groq" => {
            let key = api_key.ok_or_else(|| {
                let env = prov_cfg.api_key_env.as_deref().unwrap_or("GROQ_API_KEY");
                anyhow::anyhow!("Clé API Groq absente — définissez {}", env)
            })?;
            Ok(Box::new(OpenAiProvider::new(
                "groq", key,
                base_url.unwrap_or_else(|| "https://api.groq.com".to_string()),
                model, max_tokens, temperature,
            )))
        }
        "ollama" => {
            let url = base_url.unwrap_or_else(|| "http://localhost:11434".to_string());
            Ok(Box::new(OllamaProvider::new(url, model, max_tokens, temperature)))
        }
        other => bail!("Provider '{}' non supporté", other),
    }
}
