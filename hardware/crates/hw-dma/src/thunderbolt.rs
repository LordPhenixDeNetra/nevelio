use hw_core::{HardwareFinding, HwSeverity, read_sysfs};
use rust_i18n::t;

pub(super) fn check_thunderbolt() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Chercher les domaines Thunderbolt dans sysfs
    let tb_base = "/sys/bus/thunderbolt/devices";
    let tb_exists = std::path::Path::new(tb_base).exists();
    if !tb_exists {
        return findings; // Thunderbolt non supporté / non détecté — skip silencieux
    }

    // Trouver le niveau de sécurité du premier domaine
    let security_path = format!("{}/domain0/security", tb_base);
    let security_level = read_sysfs(&security_path)
        .map(|s| s.trim().to_string());

    let level = match &security_level {
        None => return findings,
        Some(l) => l.clone(),
    };

    match level.as_str() {
        "none" => {
            findings.push(HardwareFinding::new(
                t!("dma.thunderbolt.none.title").to_string(),
                t!("dma.thunderbolt.none.desc").to_string(),
                HwSeverity::Critical,
                "hw-dma",
                Some(284),
                Some(9.0),
                format!("{} = \"{}\"", security_path, level),
                t!("dma.thunderbolt.none.rem").to_string(),
            ));
        }
        "user" => {
            findings.push(HardwareFinding::new(
                t!("dma.thunderbolt.user.title").to_string(),
                t!("dma.thunderbolt.user.desc").to_string(),
                HwSeverity::Medium,
                "hw-dma",
                Some(284),
                Some(5.5),
                format!("{} = \"{}\"", security_path, level),
                t!("dma.thunderbolt.user.rem").to_string(),
            ));
        }
        "secure" | "dponly" | "usbonly" => {
            findings.push(HardwareFinding::new(
                t!("dma.thunderbolt.secure.title", level = level.clone()).to_string(),
                t!("dma.thunderbolt.secure.desc", level = level.clone()).to_string(),
                HwSeverity::Informative,
                "hw-dma",
                None,
                None,
                format!("{} = \"{}\"", security_path, level),
                t!("dma.thunderbolt.secure.rem").to_string(),
            ));
        }
        _ => {
            findings.push(HardwareFinding::new(
                t!("dma.thunderbolt.unknown.title", level = level.clone()).to_string(),
                t!("dma.thunderbolt.unknown.desc", level = level.clone()).to_string(),
                HwSeverity::Informative,
                "hw-dma",
                None,
                None,
                format!("{} = \"{}\"", security_path, level),
                t!("dma.thunderbolt.unknown.rem").to_string(),
            ));
        }
    }

    findings
}
