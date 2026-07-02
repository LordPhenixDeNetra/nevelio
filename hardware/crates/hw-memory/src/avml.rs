use hw_core::{run_command, HardwareFinding, HwSeverity};
use rust_i18n::t;
use std::path::Path;

const AVML_OUTPUT: &str = "/tmp/nevelio_memory.lime";
#[cfg(target_os = "linux")]
const LIME_MODULE: &str = "/tmp/lime.ko";

/// Vérifie si avml (Azure Volatile Memory Library) est installé.
pub fn detect_avml() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let avml_present = run_command("which", &["avml"]).map_or(false, |o| !o.trim().is_empty());

    if avml_present {
        findings.push(HardwareFinding::new(
            t!("memory.avml.detected.title"),
            t!("memory.avml.detected.desc"),
            HwSeverity::Medium,
            "hw-memory",
            Some(1342),
            Some(5.5),
            "which avml → trouvé",
            t!("memory.avml.detected.rem"),
        ));
    } else {
        findings.push(HardwareFinding::new(
            t!("memory.avml.missing.title"),
            t!("memory.avml.missing.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "which avml → introuvable",
            t!("memory.avml.missing.rem"),
        ));
    }

    findings
}

/// Lance un dump mémoire via avml (uniquement en mode actif).
pub fn run_avml_dump() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if run_command("which", &["avml"]).map_or(true, |o| o.trim().is_empty()) {
        findings.push(HardwareFinding::new(
            t!("memory.avml.dump_skip.title"),
            t!("memory.avml.dump_skip.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "avml introuvable",
            t!("memory.avml.dump_skip.rem"),
        ));
        return findings;
    }

    // avml nécessite les droits root
    let output = run_command("avml", &[AVML_OUTPUT]);

    match output {
        None => {
            findings.push(HardwareFinding::new(
                t!("memory.avml.failed.title"),
                t!("memory.avml.failed.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("avml {} → échec lancement", AVML_OUTPUT),
                t!("memory.avml.failed.rem"),
            ));
        }
        Some(_) if Path::new(AVML_OUTPUT).exists() => {
            let size = std::fs::metadata(AVML_OUTPUT)
                .map(|m| m.len())
                .unwrap_or(0);
            let mb = size as f64 / 1_048_576.0;
            findings.push(HardwareFinding::new(
                t!("memory.avml.ok.title", mb = mb),
                t!("memory.avml.ok.desc", path = AVML_OUTPUT),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                t!("memory.avml.ok.evidence", path = AVML_OUTPUT, size = size),
                t!("memory.avml.ok.rem"),
            ));
        }
        Some(out) => {
            findings.push(HardwareFinding::new(
                t!("memory.avml.unexpected.title"),
                t!("memory.avml.unexpected.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                out.chars().take(300).collect::<String>(),
                t!("memory.avml.unexpected.rem"),
            ));
        }
    }

    findings
}

/// Charge le module LiME si le .ko est disponible.
#[cfg(target_os = "linux")]
pub fn run_lime_dump(output_path: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if !Path::new(LIME_MODULE).exists() {
        findings.push(HardwareFinding::new(
            t!("memory.lime.missing.title"),
            t!("memory.lime.missing.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("{} introuvable", LIME_MODULE),
            t!("memory.lime.missing.rem"),
        ));
        return findings;
    }

    let format_path = format!("path={},format=lime", output_path);
    let out = run_command("insmod", &[LIME_MODULE, &format_path]);

    if out.is_some() {
        findings.push(HardwareFinding::new(
            t!("memory.lime.ok.title"),
            format!(
                "LiME a été inséré avec format=lime, sortie : {}. \
                 Le fichier sera disponible après l'écriture complète.",
                output_path
            ),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("insmod {} path={},format=lime", LIME_MODULE, output_path),
            t!("memory.lime.ok.rem"),
        ));
    }

    findings
}

#[cfg(not(target_os = "linux"))]
pub fn run_lime_dump(_output_path: &str) -> Vec<HardwareFinding> {
    vec![HardwareFinding::new(
        t!("memory.lime.linux_only.title"),
        t!("memory.lime.linux_only.desc"),
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        format!("OS : {}", std::env::consts::OS),
        t!("memory.lime.linux_only.rem"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avml_detection_does_not_panic() {
        let findings = detect_avml();
        assert!(!findings.is_empty());
    }

    #[test]
    fn lime_dump_non_linux_informative() {
        #[cfg(not(target_os = "linux"))]
        {
            let findings = run_lime_dump("/tmp/test.lime");
            assert!(!findings.is_empty());
        }
        // Sur Linux, le test évite insmod (root requis)
        #[cfg(target_os = "linux")]
        {
            // Le fichier /tmp/lime.ko n'existe pas → finding informatif
            let findings = run_lime_dump("/tmp/test.lime");
            assert!(!findings.is_empty());
        }
    }
}
