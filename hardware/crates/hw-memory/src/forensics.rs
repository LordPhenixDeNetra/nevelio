use hw_core::{run_command, HardwareFinding, HwSeverity};
use rust_i18n::t;

const VOL_SCRIPT: &str = "hardware/python/volatility_runner.py";

/// Lance l'analyse Volatility 3 sur un dump mémoire.
pub fn run_volatility_analysis(dump_path: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if !std::path::Path::new(dump_path).exists() {
        findings.push(HardwareFinding::new(
            t!("memory.forensics.dump_missing.title"),
            t!("memory.forensics.dump_missing.desc", path = dump_path),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            dump_path.to_string(),
            t!("memory.forensics.dump_missing.rem"),
        ));
        return findings;
    }

    let python = if run_command("python3", &["--version"]).is_some() { "python3" }
                 else if run_command("python", &["--version"]).is_some() { "python" }
                 else {
                     findings.push(HardwareFinding::new(
                         t!("memory.forensics.python_missing.title"),
                         t!("memory.forensics.python_missing.desc"),
                         HwSeverity::Informative,
                         "hw-memory",
                         None, None,
                         "python3 absent du PATH",
                         t!("memory.forensics.python_missing.rem"),
                     ));
                     return findings;
                 };

    let output = run_command(python, &[VOL_SCRIPT, "--dump", dump_path]);

    let json_str = match output {
        Some(o) if !o.trim().is_empty() => o,
        _ => {
            findings.push(HardwareFinding::new(
                t!("memory.forensics.vol_empty.title"),
                t!("memory.forensics.vol_empty.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("{} --dump {}", VOL_SCRIPT, dump_path),
                t!("memory.forensics.vol_empty.rem"),
            ));
            return findings;
        }
    };

    match serde_json::from_str::<serde_json::Value>(&json_str) {
        Err(e) => {
            findings.push(HardwareFinding::new(
                t!("memory.forensics.json_error.title"),
                t!("memory.forensics.json_error.desc", error = e),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                json_str.chars().take(200).collect::<String>(),
                "",
            ));
        }
        Ok(result) => {
            // Trouver quel OS a été détecté
            let os_name = result.get("dump")
                .and_then(|d| d.get("os"))
                .and_then(|o| o.as_str())
                .unwrap_or("inconnu");

            let vol_version = result.get("volatility")
                .and_then(|v| v.as_str())
                .unwrap_or("absent");

            if vol_version == "absent" {
                findings.push(HardwareFinding::new(
                    t!("memory.forensics.vol_absent.title"),
                    t!("memory.forensics.vol_absent.desc"),
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    "vol3 introuvable",
                    t!("memory.forensics.vol_absent.rem"),
                ));
            } else {
                findings.push(HardwareFinding::new(
                    t!("memory.forensics.vol_ok.title", ver = vol_version, os = os_name),
                    t!("memory.forensics.vol_ok.desc", os = os_name),
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    format!("dump={}, vol={}", dump_path, vol_version),
                    "",
                ));
            }

            // Parser les findings retournés par le script Python
            if let Some(fw_findings) = result.get("findings").and_then(|f| f.as_array()) {
                for f in fw_findings {
                    let severity = match f.get("severity").and_then(|s| s.as_str()) {
                        Some("CRITICAL") => HwSeverity::Critical,
                        Some("HIGH")     => HwSeverity::High,
                        Some("MEDIUM")   => HwSeverity::Medium,
                        Some("LOW")      => HwSeverity::Low,
                        _                => HwSeverity::Informative,
                    };

                    findings.push(HardwareFinding::new(
                        f.get("title").and_then(|v| v.as_str()).unwrap_or("Finding forensic"),
                        f.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                        severity,
                        "hw-memory",
                        f.get("cwe").and_then(|v| v.as_u64()).map(|v| v as u32),
                        f.get("cvss").and_then(|v| v.as_f64()).map(|v| v as f32),
                        f.get("evidence").and_then(|v| v.as_str()).unwrap_or(""),
                        f.get("remediation").and_then(|v| v.as_str()).unwrap_or(""),
                    ));
                }
            }
        }
    }

    findings
}

/// Vérifie la configuration des core dumps.
pub fn check_core_dumps() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Lire le pattern de core dump
    #[cfg(target_os = "linux")]
    {
        let core_pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern")
            .unwrap_or_default();
        let core_pattern = core_pattern.trim();

        if core_pattern.is_empty() || core_pattern == "core" {
            findings.push(HardwareFinding::new(
                t!("memory.core.active.title"),
                t!("memory.core.active.desc"),
                HwSeverity::Medium,
                "hw-memory",
                Some(312),
                Some(5.5),
                format!("/proc/sys/kernel/core_pattern = '{}'", core_pattern),
                t!("memory.core.active.rem"),
            ));
        } else if core_pattern.starts_with('|') {
            // Core dump via pipe (systemd-coredump, apport, etc.)
            findings.push(HardwareFinding::new(
                t!("memory.core.pipe.title"),
                t!("memory.core.pipe.desc", pattern = core_pattern),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("/proc/sys/kernel/core_pattern = '{}'", core_pattern),
                t!("memory.core.pipe.rem"),
            ));
        }

        // Vérifier core_uses_pid
        let core_pid = std::fs::read_to_string("/proc/sys/kernel/core_uses_pid")
            .unwrap_or_default();
        let _ = core_pid; // informatif uniquement

        // Vérifier si core dumps sont vraiment actifs (via /proc/self/limits)
        check_ulimit_core(&mut findings);
    }

    #[cfg(not(target_os = "linux"))]
    {
        findings.push(HardwareFinding::new(
            t!("memory.core.linux_only.title"),
            t!("memory.core.linux_only.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("OS : {}", std::env::consts::OS),
            "",
        ));
    }

    findings
}

#[cfg(target_os = "linux")]
fn check_ulimit_core(findings: &mut Vec<HardwareFinding>) {
    // Lire les limites du processus courant comme proxy pour les limites système
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();

    for line in limits.lines() {
        if line.starts_with("Max core file size") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Format : "Max core file size  0  0  bytes"
            if let Some(soft) = parts.get(4) {
                if *soft == "0" {
                    findings.push(HardwareFinding::new(
                        t!("memory.core.disabled.title"),
                        t!("memory.core.disabled.desc"),
                        HwSeverity::Informative,
                        "hw-memory",
                        None, None,
                        "ulimit -c 0 (Max core file size = 0)",
                        "",
                    ));
                    return;
                } else if *soft == "unlimited" {
                    findings.push(HardwareFinding::new(
                        t!("memory.core.unlimited.title"),
                        t!("memory.core.unlimited.desc"),
                        HwSeverity::Medium,
                        "hw-memory",
                        Some(312),
                        Some(4.4),
                        "ulimit -c unlimited",
                        t!("memory.core.unlimited.rem"),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatility_missing_dump_returns_finding() {
        let findings = run_volatility_analysis("/nonexistent/memory.lime");
        assert!(!findings.is_empty());
        assert!(findings[0].severity == HwSeverity::Informative);
    }

    #[test]
    fn core_dump_check_does_not_panic() {
        let findings = check_core_dumps();
        assert!(!findings.is_empty());
    }
}
