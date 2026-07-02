use hw_core::{HardwareFinding, HwSeverity, run_command};
use rust_i18n::t;

pub(super) fn check_spi_flash() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Vérifier si flashrom est disponible
    let flashrom_available = run_command("flashrom", &["--version"]).is_some();
    if !flashrom_available {
        findings.push(HardwareFinding::new(
            t!("firmware.flash.flashrom_missing.title").to_string(),
            t!("firmware.flash.flashrom_missing.desc").to_string(),
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            "flashrom non trouvé dans le PATH",
            t!("firmware.flash.flashrom_missing.rem").to_string(),
        ));
        return findings;
    }

    // Tenter de lire le flash SPI interne
    let output = run_command("flashrom", &["-p", "internal", "--wp-status"]);

    match output {
        None => {
            findings.push(HardwareFinding::new(
                t!("firmware.flash.access_denied.title").to_string(),
                t!("firmware.flash.access_denied.desc").to_string(),
                HwSeverity::Informative,
                "hw-firmware",
                None,
                None,
                "flashrom -p internal a échoué (permissions insuffisantes ?)",
                t!("firmware.flash.access_denied.rem").to_string(),
            ));
        }
        Some(ref wp_output) => {
            let lower = wp_output.to_lowercase();

            if lower.contains("write protection is disabled") || lower.contains("wp: disabled") {
                findings.push(HardwareFinding::new(
                    t!("firmware.flash.wp_disabled.title").to_string(),
                    t!("firmware.flash.wp_disabled.desc").to_string(),
                    HwSeverity::Critical,
                    "hw-firmware",
                    Some(1266),
                    Some(9.0),
                    format!("flashrom --wp-status : {}", wp_output.trim()),
                    t!("firmware.flash.wp_disabled.rem").to_string(),
                ));
            } else if lower.contains("write protection is enabled") || lower.contains("wp: enabled") {
                findings.push(HardwareFinding::new(
                    t!("firmware.flash.wp_enabled.title").to_string(),
                    t!("firmware.flash.wp_enabled.desc").to_string(),
                    HwSeverity::Informative,
                    "hw-firmware",
                    None,
                    None,
                    "flashrom --wp-status : write protection active",
                    t!("firmware.flash.wp_enabled.rem").to_string(),
                ));
            } else {
                // flashrom a répondu mais sans mention de write protection — lecture seule possible
                findings.push(HardwareFinding::new(
                    t!("firmware.flash.wp_not_checkable.title").to_string(),
                    t!("firmware.flash.wp_not_checkable.desc").to_string(),
                    HwSeverity::Low,
                    "hw-firmware",
                    Some(1266),
                    Some(4.0),
                    format!(
                        "flashrom -p internal : succès en lecture, --wp-status non supporté sur ce chip\nSortie: {}",
                        wp_output.lines().take(5).collect::<Vec<_>>().join(" | ")
                    ),
                    t!("firmware.flash.wp_not_checkable.rem").to_string(),
                ));
            }
        }
    }

    findings
}
