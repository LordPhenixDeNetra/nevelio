use crate::types::{GlobalConfig, ProjectConfig, ResolvedConfig};

/// CLI-level overrides — supplied by the calling binary.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub lang:        Option<String>,
    pub dry_run:     Option<bool>,
    pub ai_enabled:  Option<bool>,
    pub ai_provider: Option<String>,
    pub target:      Option<String>,
    pub profile:     Option<String>,
    pub timeout:     Option<u64>,
    pub concurrency: Option<usize>,
}

/// Merge priority : CLI flags > project config > global config > defaults.
pub fn merge(
    global:    GlobalConfig,
    project:   ProjectConfig,
    overrides: CliOverrides,
) -> ResolvedConfig {
    let mut ai = global.ai.clone();

    // Project-level AI overrides
    if let Some(enabled) = project.ai.enabled {
        ai.enabled = enabled;
    }
    if let Some(ref prov) = project.ai.provider {
        ai.provider = Some(prov.clone());
    }

    // CLI-level AI overrides (highest priority)
    if let Some(enabled) = overrides.ai_enabled {
        ai.enabled = enabled;
    }
    if let Some(ref prov) = overrides.ai_provider {
        ai.provider = Some(prov.clone());
    }

    let mut scan = global.scan.clone();

    // Project overrides
    if let Some(p) = &project.profile   { scan.profile = Some(p.clone()); }
    if let Some(d) = project.dry_run    { scan.dry_run = d; }
    if let Some(t) = project.timeout    { scan.timeout_secs = t; }
    if let Some(c) = project.concurrency{ scan.concurrency = c; }
    if let Some(l) = &project.lang      { scan.lang = l.clone(); }

    // CLI overrides
    if let Some(l) = overrides.lang        { scan.lang = l; }
    if let Some(d) = overrides.dry_run     { scan.dry_run = d; }
    if let Some(p) = overrides.profile     { scan.profile = Some(p); }
    if let Some(t) = overrides.timeout     { scan.timeout_secs = t; }
    if let Some(c) = overrides.concurrency { scan.concurrency = c; }

    ResolvedConfig {
        user:   global.user,
        ai,
        scan,
        output: global.output,
        notify: global.notify,
        audit:  global.audit,
        target: overrides.target.or(project.target),
    }
}
