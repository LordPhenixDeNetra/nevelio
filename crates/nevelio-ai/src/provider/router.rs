use anyhow::Result;

use nevelio_config::AiConfig;

use super::fallback::FallbackProvider;
use super::{factory::build_named_provider, AiProvider};

// ── Task types (A.5) ──────────────────────────────────────────────────────────

/// Semantic task type used to select a provider from `ai.routing.*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    Triage,
    Remediation,
    Report,
    Payloads,
    Agent,
}

// ── Routing logic ─────────────────────────────────────────────────────────────

/// Build the best provider for a given task, honouring `ai.routing.*` and
/// wrapping the result in a `FallbackProvider` if `ai.routing.fallback` is set.
///
/// Priority:
///   1. Provider explicitly configured for this task type in `cfg.routing`
///   2. Active provider (`cfg.provider` or default)
///   3. Wrapped in `FallbackProvider` if `cfg.routing.fallback` is also configured
pub fn build_provider_for_task(cfg: &AiConfig, task: TaskType) -> Result<Box<dyn AiProvider>> {
    let active = cfg.active_provider_name();

    // Resolve task-specific provider name from routing config
    let task_name: Option<&str> = match task {
        TaskType::Triage => cfg.routing.triage.as_deref(),
        TaskType::Report => cfg.routing.report.as_deref(),
        TaskType::Payloads => cfg.routing.payloads.as_deref(),
        TaskType::Remediation => None,
        TaskType::Agent => None,
    };

    // Build primary provider: task-specific if available and different from active
    let primary: Box<dyn AiProvider> =
        match task_name {
            Some(name) if name != active && cfg.providers.contains_key(name) => {
                tracing::debug!("Routing task {:?} to provider '{}'", task, name);
                match build_named_provider(cfg, name) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                        "Provider '{}' pour task {:?} indisponible ({}), repli sur provider actif",
                        name, task, e
                    );
                        build_named_provider(cfg, active)?
                    }
                }
            }
            _ => build_named_provider(cfg, active)?,
        };

    // Optionally wrap in FallbackProvider
    if let Some(fb_name) = cfg.routing.fallback.as_deref() {
        if fb_name != primary.name() && cfg.providers.contains_key(fb_name) {
            match build_named_provider(cfg, fb_name) {
                Ok(fallback) => {
                    tracing::debug!(
                        "Fallback provider '{}' configuré pour task {:?}",
                        fb_name,
                        task
                    );
                    return Ok(Box::new(FallbackProvider::new(primary, fallback)));
                }
                Err(e) => {
                    tracing::warn!(
                        "Provider fallback '{}' indisponible ({}), pas de fallback",
                        fb_name,
                        e
                    );
                }
            }
        }
    }

    Ok(primary)
}
