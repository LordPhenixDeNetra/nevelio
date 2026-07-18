use anyhow::{Context, Result};
use nevelio_core::types::Finding;
use rhai::{Engine, Scope};

/// Runs user-provided Rhai scripts to filter or annotate findings.
///
/// Each script receives finding fields as scope variables and must return a bool:
/// `true` → keep the finding, `false` → suppress it.
///
/// Example script (`suppress_infra_info.rhai`):
/// ```rhai
/// if module == "infra" && severity == "informative" { false } else { true }
/// ```
pub struct ScriptRunner {
    engine: Engine,
    scripts: Vec<(String, String)>, // (path, source)
}

impl ScriptRunner {
    pub fn load(paths: &[String]) -> Result<Self> {
        let engine = Engine::new();
        let scripts = paths
            .iter()
            .map(|p| {
                let src = std::fs::read_to_string(p)
                    .with_context(|| format!("Script introuvable : {}", p))?;
                Ok((p.clone(), src))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { engine, scripts })
    }

    /// Filter findings: a finding is kept only if ALL scripts return `true`.
    pub fn filter_findings(&self, findings: &[Finding]) -> Vec<Finding> {
        if self.scripts.is_empty() {
            return findings.to_vec();
        }

        findings
            .iter()
            .filter(|f| {
                self.scripts.iter().all(|(path, src)| {
                    let mut scope = Scope::new();
                    scope.push("title", f.title.clone());
                    scope.push("severity", f.severity.to_string().to_lowercase());
                    scope.push("finding_module", f.module.clone());
                    scope.push("endpoint", f.endpoint.clone());
                    scope.push("method", f.method.clone());
                    scope.push("description", f.description.clone());
                    scope.push("cvss", f.cvss_score);

                    self.engine
                        .eval_with_scope::<bool>(&mut scope, src)
                        .unwrap_or_else(|e| {
                            eprintln!("  [script] {}: {}", path, e);
                            true // keep finding on script error
                        })
                })
            })
            .cloned()
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nevelio_core::types::{Finding, Severity};

    fn make_finding(module: &str, severity: Severity) -> Finding {
        Finding::new(
            format!("Test finding — {}", module),
            severity,
            7.5,
            module,
            "https://api.example.com/test",
            "GET",
        )
    }

    #[test]
    fn empty_runner_keeps_all_findings() {
        let runner = ScriptRunner {
            engine: rhai::Engine::new(),
            scripts: vec![],
        };
        let findings = vec![make_finding("auth", Severity::High)];
        assert_eq!(runner.filter_findings(&findings).len(), 1);
    }

    #[test]
    fn script_returning_true_keeps_finding() {
        let runner = ScriptRunner {
            engine: rhai::Engine::new(),
            scripts: vec![("inline".to_string(), "true".to_string())],
        };
        let findings = vec![make_finding("auth", Severity::High)];
        assert_eq!(runner.filter_findings(&findings).len(), 1);
    }

    #[test]
    fn script_returning_false_suppresses_finding() {
        let runner = ScriptRunner {
            engine: rhai::Engine::new(),
            scripts: vec![("inline".to_string(), "false".to_string())],
        };
        let findings = vec![make_finding("auth", Severity::High)];
        assert_eq!(runner.filter_findings(&findings).len(), 0);
    }

    #[test]
    fn script_filters_by_module() {
        let runner = ScriptRunner {
            engine: rhai::Engine::new(),
            scripts: vec![(
                "inline".to_string(),
                r#"finding_module != "infra""#.to_string(),
            )],
        };
        let findings = vec![
            make_finding("auth", Severity::High),
            make_finding("infra", Severity::Informative),
        ];
        let result = runner.filter_findings(&findings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].module, "auth");
    }

    #[test]
    fn script_error_keeps_finding() {
        let runner = ScriptRunner {
            engine: rhai::Engine::new(),
            scripts: vec![("inline".to_string(), "this_is_invalid_rhai !!!".to_string())],
        };
        let findings = vec![make_finding("auth", Severity::High)];
        assert_eq!(runner.filter_findings(&findings).len(), 1);
    }
}
