// Interface haut-niveau PCILeech via leechcore.
// Documente les patterns d'attaque DMA pour l'audit de sécurité.

use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;

/// Résultat d'un scan DMA.
pub struct DmaScanResult {
    pub pa_start:    u64,
    pub pa_end:      u64,
    pub bytes_read:  u64,
    pub findings:    Vec<HardwareFinding>,
}

/// Vérifie si un IOMMU/VT-d est actif (protection DMA).
pub fn check_iommu_status() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Suppression du warning mut inutile sur macOS (le bloc Linux l'utilise)
    #[allow(unused_mut)]
    let _ = &mut findings;

    #[cfg(target_os = "linux")]
    {
        // Vérification IOMMU via dmesg
        let dmesg = hw_core::run_command("dmesg", &["--notime"]);
        let iommu_active = dmesg.as_deref().unwrap_or("")
            .lines()
            .any(|l| l.contains("IOMMU enabled") || l.contains("Intel-IOMMU: enabled")
                  || l.contains("AMD-Vi: initialized"));

        if iommu_active {
            findings.push(HardwareFinding::new(
                t!("fpga.iommu.active.title"),
                t!("fpga.iommu.active.desc"),
                HwSeverity::Informative,
                "hw-dma-fpga",
                None, None,
                "dmesg: IOMMU enabled",
                t!("fpga.iommu.active.rem"),
            ));
        } else {
            // Vérifier via /sys
            let iommu_sys = std::fs::read_dir("/sys/class/iommu")
                .map(|d| d.count() > 0)
                .unwrap_or(false);

            if !iommu_sys {
                findings.push(HardwareFinding::new(
                    t!("fpga.iommu.missing.title"),
                    t!("fpga.iommu.missing.desc"),
                    HwSeverity::High,
                    "hw-dma-fpga",
                    Some(1274),
                    Some(7.6),
                    "dmesg: IOMMU non mentionné; /sys/class/iommu: vide",
                    t!("fpga.iommu.missing.rem"),
                ));
            }
        }

        // Vérifier le mode strict IOMMU
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if !cmdline.contains("iommu=force") && !cmdline.contains("iommu=strict") {
            findings.push(HardwareFinding::new(
                t!("fpga.iommu.strict.title"),
                t!("fpga.iommu.strict.desc"),
                HwSeverity::Medium,
                "hw-dma-fpga",
                Some(1274),
                Some(5.9),
                &cmdline,
                t!("fpga.iommu.strict.rem"),
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    findings.push(HardwareFinding::new(
        t!("fpga.iommu.unknown.title"),
        t!("fpga.iommu.unknown.desc"),
        HwSeverity::Informative,
        "hw-dma-fpga",
        None, None,
        "plateforme non-Linux",
        t!("fpga.iommu.unknown.rem"),
    ));

    findings
}

/// Vérifie si Thunderbolt avec DMA est activé (risque BadUSB/Thunderclap).
pub fn check_thunderbolt_dma() -> Vec<HardwareFinding> {
    #[allow(unused_mut)]
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Vérification du niveau de sécurité Thunderbolt
        let tb_paths = [
            "/sys/bus/thunderbolt/devices/0-0/security",
            "/sys/bus/thunderbolt/devices/domain0/security",
        ];

        for path in &tb_paths {
            if let Ok(level) = std::fs::read_to_string(path) {
                let level = level.trim();
                let (sev, title_key, rem_key): (HwSeverity, &str, &str) = match level {
                    "none" => (
                        HwSeverity::Critical,
                        "fpga.thunderbolt.none_sec.title",
                        "fpga.thunderbolt.none_sec.rem",
                    ),
                    "user" => (
                        HwSeverity::Medium,
                        "fpga.thunderbolt.user_sec.title",
                        "fpga.thunderbolt.user_sec.rem",
                    ),
                    "secure" | "dponly" | "usbonly" => (
                        HwSeverity::Informative,
                        "fpga.thunderbolt.secure_sec.title",
                        "",
                    ),
                    _ => (
                        HwSeverity::Low,
                        "fpga.thunderbolt.unknown_sec.title",
                        "fpga.thunderbolt.unknown_sec.rem",
                    ),
                };

                findings.push(HardwareFinding::new(
                    t!(title_key),
                    t!("fpga.thunderbolt.desc", level = level),
                    sev,
                    "hw-dma-fpga",
                    Some(284),
                    None,
                    t!("fpga.thunderbolt.evidence", path = path, level = level),
                    if rem_key.is_empty() { String::new() } else { t!(rem_key) },
                ));
                break;
            }
        }
    }

    findings
}

/// Scan passif — vérifie IOMMU + Thunderbolt sans accès DMA réel.
pub fn run_passive_dma_audit() -> Vec<HardwareFinding> {
    let mut findings = check_iommu_status();
    findings.extend(check_thunderbolt_dma());
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_audit_does_not_panic() {
        let f = run_passive_dma_audit();
        assert!(!f.is_empty());
    }

    #[test]
    fn iommu_check_does_not_panic() {
        let _ = check_iommu_status();
    }
}
