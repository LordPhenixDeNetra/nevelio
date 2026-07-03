use crate::types::ResolvedConfig;

const KNOWN_LANGS: &[&str]      = &["fr", "en", "es"];
const KNOWN_PROFILES: &[&str]   = &["stealth", "normal", "aggressive"];
const KNOWN_FORMATS: &[&str]    = &["text", "json", "html", "markdown"];
const KNOWN_PROVIDERS: &[&str]  = &["anthropic", "openai", "mistral", "groq", "ollama", "bedrock"];

/// A single semantic validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Dotted path to the offending field (e.g. "scan.lang").
    pub field: String,
    /// Human-readable message (in English — displayed before i18n is set up).
    pub message: String,
}

impl ValidationError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self { field: field.into(), message: message.into() }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.field, self.message)
    }
}

/// Validate a resolved config semantically.
///
/// Returns all errors found (not just the first).  Callers should display them
/// all and then bail — never silently ignore a non-empty list.
pub fn validate(cfg: &ResolvedConfig) -> Vec<ValidationError> {
    let mut errors: Vec<ValidationError> = Vec::new();

    validate_scan(cfg, &mut errors);
    validate_output(cfg, &mut errors);
    validate_ai(cfg, &mut errors);
    validate_user(cfg, &mut errors);

    errors
}

// ── scan.* ───────────────────────────────────────────────────────────────────

fn validate_scan(cfg: &ResolvedConfig, errors: &mut Vec<ValidationError>) {
    let scan = &cfg.scan;

    if !KNOWN_LANGS.contains(&scan.lang.as_str()) {
        errors.push(ValidationError::new(
            "scan.lang",
            format!(
                "unknown locale {:?}; allowed values: {}",
                scan.lang,
                KNOWN_LANGS.join(", ")
            ),
        ));
    }

    if let Some(ref profile) = scan.profile {
        if !KNOWN_PROFILES.contains(&profile.as_str()) {
            errors.push(ValidationError::new(
                "scan.profile",
                format!(
                    "unknown profile {:?}; allowed values: {}",
                    profile,
                    KNOWN_PROFILES.join(", ")
                ),
            ));
        }
    }

    if scan.timeout_secs == 0 {
        errors.push(ValidationError::new(
            "scan.timeout_secs",
            "timeout must be at least 1 second",
        ));
    } else if scan.timeout_secs > 3600 {
        errors.push(ValidationError::new(
            "scan.timeout_secs",
            format!("timeout {}s exceeds maximum of 3600s (1 hour)", scan.timeout_secs),
        ));
    }

    if scan.concurrency == 0 {
        errors.push(ValidationError::new(
            "scan.concurrency",
            "concurrency must be at least 1",
        ));
    } else if scan.concurrency > 500 {
        errors.push(ValidationError::new(
            "scan.concurrency",
            format!("concurrency {} exceeds maximum of 500", scan.concurrency),
        ));
    }
}

// ── output.* ─────────────────────────────────────────────────────────────────

fn validate_output(cfg: &ResolvedConfig, errors: &mut Vec<ValidationError>) {
    let fmt = cfg.output.format.as_str();
    if !KNOWN_FORMATS.contains(&fmt) {
        errors.push(ValidationError::new(
            "output.format",
            format!(
                "unknown format {:?}; allowed values: {}",
                fmt,
                KNOWN_FORMATS.join(", ")
            ),
        ));
    }
}

// ── ai.* ─────────────────────────────────────────────────────────────────────

fn is_known_or_configured(name: &str, cfg: &ResolvedConfig) -> bool {
    KNOWN_PROVIDERS.contains(&name) || cfg.ai.providers.contains_key(name)
}

fn validate_ai(cfg: &ResolvedConfig, errors: &mut Vec<ValidationError>) {
    if !cfg.ai.enabled {
        return;
    }

    let active = cfg.ai.active_provider_name();
    if !is_known_or_configured(active, cfg) {
        errors.push(ValidationError::new(
            "ai.provider",
            format!(
                "unknown provider {:?}; built-in providers: {}",
                active,
                KNOWN_PROVIDERS.join(", ")
            ),
        ));
    }

    // routing fields
    let routing_checks = [
        ("ai.routing.triage",   cfg.ai.routing.triage.as_deref()),
        ("ai.routing.report",   cfg.ai.routing.report.as_deref()),
        ("ai.routing.payloads", cfg.ai.routing.payloads.as_deref()),
        ("ai.routing.fallback", cfg.ai.routing.fallback.as_deref()),
    ];
    for (field, opt) in routing_checks {
        if let Some(name) = opt {
            if !is_known_or_configured(name, cfg) {
                errors.push(ValidationError::new(
                    field,
                    format!(
                        "unknown provider {:?}; built-in providers: {}",
                        name,
                        KNOWN_PROVIDERS.join(", ")
                    ),
                ));
            }
        }
    }

    // per-provider config
    for (name, prov) in &cfg.ai.providers {
        let prefix = format!("ai.providers.{}", name);

        if let Some(temp) = prov.temperature {
            if !(0.0..=2.0).contains(&temp) {
                errors.push(ValidationError::new(
                    format!("{}.temperature", prefix),
                    format!("temperature {temp} must be in [0.0, 2.0]"),
                ));
            }
        }

        if let Some(max_tok) = prov.max_tokens {
            if max_tok == 0 {
                errors.push(ValidationError::new(
                    format!("{}.max_tokens", prefix),
                    "max_tokens must be at least 1",
                ));
            } else if max_tok > 128_000 {
                errors.push(ValidationError::new(
                    format!("{}.max_tokens", prefix),
                    format!("max_tokens {max_tok} exceeds maximum of 128 000"),
                ));
            }
        }

        if prov.model.is_empty() {
            errors.push(ValidationError::new(
                format!("{}.model", prefix),
                "model name must not be empty",
            ));
        }
    }
}

// ── user.* ───────────────────────────────────────────────────────────────────

fn validate_user(cfg: &ResolvedConfig, errors: &mut Vec<ValidationError>) {
    if let Some(ref email) = cfg.user.email {
        if !email.contains('@') {
            errors.push(ValidationError::new(
                "user.email",
                format!("invalid email address {:?} (must contain '@')", email),
            ));
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{GlobalConfig, ProviderConfig, ResolvedConfig};
    use crate::merge::{merge, CliOverrides};

    fn resolved_default() -> ResolvedConfig {
        merge(GlobalConfig::default(), Default::default(), CliOverrides::default())
    }

    #[test]
    fn valid_default_config_has_no_errors() {
        let cfg = resolved_default();
        assert!(validate(&cfg).is_empty(), "Default config should be valid");
    }

    #[test]
    fn invalid_lang_is_reported() {
        let mut cfg = resolved_default();
        cfg.scan.lang = "xx".to_string();
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "scan.lang"), "Expected scan.lang error, got: {:?}", errs);
    }

    #[test]
    fn invalid_profile_is_reported() {
        let mut cfg = resolved_default();
        cfg.scan.profile = Some("turbo".to_string());
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "scan.profile"), "Expected scan.profile error");
    }

    #[test]
    fn zero_timeout_is_reported() {
        let mut cfg = resolved_default();
        cfg.scan.timeout_secs = 0;
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "scan.timeout_secs"));
    }

    #[test]
    fn excessive_timeout_is_reported() {
        let mut cfg = resolved_default();
        cfg.scan.timeout_secs = 9999;
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "scan.timeout_secs"));
    }

    #[test]
    fn zero_concurrency_is_reported() {
        let mut cfg = resolved_default();
        cfg.scan.concurrency = 0;
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "scan.concurrency"));
    }

    #[test]
    fn invalid_output_format_is_reported() {
        let mut cfg = resolved_default();
        cfg.output.format = "pdf".to_string();
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "output.format"));
    }

    #[test]
    fn unknown_ai_provider_is_reported() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("unknown_llm".to_string());
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "ai.provider"));
    }

    #[test]
    fn known_built_in_provider_is_valid() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("anthropic".to_string());
        assert!(validate(&cfg).is_empty());
    }

    #[test]
    fn custom_provider_in_providers_map_is_valid() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("my_custom".to_string());
        cfg.ai.providers.insert("my_custom".to_string(), ProviderConfig {
            model: "gpt-custom".to_string(),
            ..Default::default()
        });
        assert!(validate(&cfg).is_empty());
    }

    #[test]
    fn invalid_routing_provider_is_reported() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("anthropic".to_string());
        cfg.ai.routing.fallback = Some("nonexistent".to_string());
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "ai.routing.fallback"));
    }

    #[test]
    fn temperature_out_of_range_is_reported() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("anthropic".to_string());
        cfg.ai.providers.insert("anthropic".to_string(), ProviderConfig {
            model: "claude-sonnet-4-6".to_string(),
            temperature: Some(3.5),
            ..Default::default()
        });
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field.contains("temperature")));
    }

    #[test]
    fn empty_model_is_reported() {
        let mut cfg = resolved_default();
        cfg.ai.enabled = true;
        cfg.ai.provider = Some("anthropic".to_string());
        cfg.ai.providers.insert("anthropic".to_string(), ProviderConfig {
            model: String::new(),
            ..Default::default()
        });
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field.contains("model")));
    }

    #[test]
    fn invalid_email_is_reported() {
        let mut cfg = resolved_default();
        cfg.user.email = Some("not-an-email".to_string());
        let errs = validate(&cfg);
        assert!(errs.iter().any(|e| e.field == "user.email"));
    }

    #[test]
    fn valid_email_passes() {
        let mut cfg = resolved_default();
        cfg.user.email = Some("alice@example.com".to_string());
        assert!(validate(&cfg).is_empty());
    }

    #[test]
    fn multiple_errors_collected() {
        let mut cfg = resolved_default();
        cfg.scan.lang = "xx".to_string();
        cfg.scan.timeout_secs = 0;
        cfg.output.format = "pdf".to_string();
        let errs = validate(&cfg);
        assert!(errs.len() >= 3, "Expected at least 3 errors, got: {:?}", errs);
    }
}
