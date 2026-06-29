use hw_core::{run_command, HardwareFinding, HwSeverity};

/// Exécute l'audit OpenOCD avec `tcl/jtag_audit.tcl` et parse la sortie.
/// Retourne les findings extraits des lignes NEVELIO_FINDING:.
pub fn run_openocd_audit(
    interface_cfg: &str,
    target_cfg:    &str,
    target_name:   &str,
    dry_run:       bool,
    tcl_script:    &str,
) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if run_command("openocd", &["--version"]).is_none() {
        findings.push(HardwareFinding::new(
            "OpenOCD non installé — audit JTAG ignoré",
            "OpenOCD est requis pour l'audit JTAG/SWD. \
             Installer : apt-get install openocd",
            HwSeverity::Informative,
            "hw-jtag",
            None, None,
            "openocd absent du PATH",
            "sudo apt-get install openocd",
        ));
        return findings;
    }

    let dry_run_str = if dry_run { "1" } else { "0" };

    // Construire la commande OpenOCD
    // -c permet de passer des commandes Tcl inline avant le script
    let output = run_command("openocd", &[
        "-f", interface_cfg,
        "-f", target_cfg,
        "-c", &format!("set TARGET {}; set DRY_RUN {}", target_name, dry_run_str),
        "-f", tcl_script,
        "-c", "exit",
    ]);

    let raw = match output {
        Some(o) => o,
        None    => {
            findings.push(HardwareFinding::new(
                "Échec lancement OpenOCD",
                "openocd n'a pas pu démarrer. Vérifier l'interface et le target configurés.",
                HwSeverity::Informative,
                "hw-jtag",
                None, None,
                format!("interface={}, target={}", interface_cfg, target_cfg),
                "Vérifier le câblage et les fichiers de configuration OpenOCD.",
            ));
            return findings;
        }
    };

    // Parser les lignes NEVELIO_FINDING:
    parse_openocd_output(&raw, &mut findings);

    if findings.iter().all(|f| matches!(f.severity, HwSeverity::Informative)) {
        // Aucun finding de sécurité — vérifier si openocd a bien communiqué avec la cible
        if raw.contains("Error") || raw.contains("error") {
            findings.push(HardwareFinding::new(
                "OpenOCD : erreur de connexion à la cible",
                "OpenOCD a démarré mais n'a pas pu communiquer avec la cible JTAG. \
                 Vérifier le câblage, la tension et la configuration.",
                HwSeverity::Informative,
                "hw-jtag",
                None, None,
                raw.lines()
                   .filter(|l| l.to_lowercase().contains("error"))
                   .take(3)
                   .collect::<Vec<_>>()
                   .join(" | "),
                "Consulter la documentation OpenOCD pour votre interface et target.",
            ));
        }
    }

    findings
}

/// Parse les lignes `NEVELIO_FINDING:<ID>:<SEVERITY>:<TITRE>:<DETAIL>`.
fn parse_openocd_output(output: &str, findings: &mut Vec<HardwareFinding>) {
    for line in output.lines() {
        let line = line.trim();
        if !line.starts_with("NEVELIO_FINDING:") {
            continue;
        }

        // Format : NEVELIO_FINDING:ID:SEVERITY:TITRE:DETAIL
        let parts: Vec<&str> = line.splitn(5, ':').collect();
        if parts.len() < 5 {
            continue;
        }

        let _id      = parts[1];
        let severity = parts[2];
        let title    = parts[3];
        let detail   = parts[4];

        let hw_severity = match severity {
            "CRITICAL"    => HwSeverity::Critical,
            "HIGH"        => HwSeverity::High,
            "MEDIUM"      => HwSeverity::Medium,
            "LOW"         => HwSeverity::Low,
            _             => HwSeverity::Informative,
        };

        let cwe = if title.contains("RDP") || title.contains("flash") {
            Some(1240)
        } else {
            None
        };

        let cvss = match hw_severity {
            HwSeverity::Critical => Some(9.8),
            HwSeverity::High     => Some(7.5),
            HwSeverity::Medium   => Some(5.3),
            _                    => None,
        };

        findings.push(HardwareFinding::new(
            title,
            detail,
            hw_severity,
            "hw-jtag",
            cwe,
            cvss,
            format!("OpenOCD: {}", line),
            remediation_for(title),
        ));
    }
}

fn remediation_for(title: &str) -> &'static str {
    if title.contains("Level 0") || title.contains("LEVEL0") {
        "Activer le Read Protection Level 1 ou 2 via STM32CubeProgrammer ou OpenOCD : \
         stm32f4x option_write 0 0xXX — ATTENTION : Level 2 est irréversible."
    } else if title.contains("PCROP") {
        "Activer PCROP via STM32CubeProgrammer pour protéger les régions sensibles."
    } else if title.contains("UART") || title.contains("bootloader") {
        "Configurer BOOT0 = 0 en production pour démarrer depuis la flash principale."
    } else {
        "Consulter la note applicative AN4701 (STM) ou le référentiel ENISA pour les bonnes pratiques JTAG."
    }
}

/// Lance l'audit firmware via le script Python.
pub fn run_firmware_analyzer(
    firmware_path: &str,
    python_script: &str,
    no_r2: bool,
) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if !std::path::Path::new(firmware_path).exists() {
        findings.push(HardwareFinding::new(
            "Firmware introuvable",
            format!("Le fichier {} n'existe pas.", firmware_path),
            HwSeverity::Informative,
            "hw-jtag",
            None, None,
            firmware_path.to_string(),
            "Fournir le chemin vers un fichier firmware valide.",
        ));
        return findings;
    }

    let python = if run_command("python3", &["--version"]).is_some() {
        "python3"
    } else if run_command("python", &["--version"]).is_some() {
        "python"
    } else {
        findings.push(HardwareFinding::new(
            "Python non disponible — analyse firmware ignorée",
            "python3 est requis pour firmware_analyzer.py.",
            HwSeverity::Informative,
            "hw-jtag",
            None, None,
            "python3 absent",
            "sudo apt-get install python3",
        ));
        return findings;
    };

    let mut args = vec!["--firmware", firmware_path];
    if no_r2 { args.push("--no-r2"); }

    let output = run_command(python, &{
        let mut full = vec![python_script];
        full.extend(args);
        full
    });

    let json_str = match output {
        Some(o) => o,
        None    => {
            findings.push(HardwareFinding::new(
                "Échec du script firmware_analyzer.py",
                "Le script Python n'a pas produit de sortie.",
                HwSeverity::Informative,
                "hw-jtag",
                None, None,
                python_script.to_string(),
                "Vérifier que firmware_analyzer.py est accessible et que les dépendances sont installées.",
            ));
            return findings;
        }
    };

    // Parser le JSON retourné par firmware_analyzer.py
    match serde_json::from_str::<serde_json::Value>(&json_str) {
        Err(e) => {
            findings.push(HardwareFinding::new(
                "Erreur de parsing JSON firmware_analyzer",
                format!("Le script a retourné un JSON invalide : {}", e),
                HwSeverity::Informative,
                "hw-jtag",
                None, None,
                json_str.chars().take(200).collect::<String>(),
                "Vérifier la sortie de firmware_analyzer.py manuellement.",
            ));
        }
        Ok(result) => {
            if let Some(fw_findings) = result.get("findings").and_then(|f| f.as_array()) {
                for f in fw_findings {
                    let severity = match f.get("severity").and_then(|s| s.as_str()) {
                        Some("CRITICAL")    => HwSeverity::Critical,
                        Some("HIGH")        => HwSeverity::High,
                        Some("MEDIUM")      => HwSeverity::Medium,
                        Some("LOW")         => HwSeverity::Low,
                        _                   => HwSeverity::Informative,
                    };

                    findings.push(HardwareFinding::new(
                        f.get("title").and_then(|v| v.as_str()).unwrap_or("Finding firmware"),
                        f.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                        severity,
                        "hw-jtag",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nevelio_finding_line() {
        let output = "NEVELIO_FINDING:STM32_RDP_LEVEL0:CRITICAL:RDP Level 0 actif:Aucune protection";
        let mut findings = Vec::new();
        parse_openocd_output(output, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, HwSeverity::Critical);
        assert!(findings[0].title.contains("RDP Level 0"));
    }

    #[test]
    fn parse_informative_finding() {
        let output = "NEVELIO_FINDING:DAP_OK:INFORMATIVE:DAP accessible:Connexion OK";
        let mut findings = Vec::new();
        parse_openocd_output(output, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, HwSeverity::Informative);
    }

    #[test]
    fn parse_empty_output() {
        let mut findings = Vec::new();
        parse_openocd_output("OpenOCD 0.12.0 started\nInfo: ...", &mut findings);
        assert!(findings.is_empty());
    }
}
