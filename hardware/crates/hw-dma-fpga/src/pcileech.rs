// Interface haut-niveau PCILeech via leechcore.
// Documente les patterns d'attaque DMA pour l'audit de sécurité.

use hw_core::{HardwareFinding, HwSeverity};

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
                "IOMMU actif — protection DMA en place",
                "L'IOMMU (Intel VT-d ou AMD-Vi) est activé sur ce système. \
                 Les attaques DMA via PCILeech-FPGA seront partiellement ou \
                 totalement bloquées selon la configuration des groupes IOMMU.",
                HwSeverity::Informative,
                "hw-dma-fpga",
                None, None,
                "dmesg: IOMMU enabled",
                "Configuration recommandée : activer strict mode (iommu=force) \
                 et vérifier que tous les devices sont dans des groupes distincts.",
            ));
        } else {
            // Vérifier via /sys
            let iommu_sys = std::fs::read_dir("/sys/class/iommu")
                .map(|d| d.count() > 0)
                .unwrap_or(false);

            if !iommu_sys {
                findings.push(HardwareFinding::new(
                    "IOMMU non détecté — DMA physique potentiellement accessible",
                    "Aucun IOMMU (Intel VT-d / AMD-Vi) n'a été détecté sur ce système. \
                     Un attaquant avec accès physique PCIe peut lire la mémoire physique \
                     complète via un FPGA (PCILeech) ou un adaptateur Thunderbolt malveillant.",
                    HwSeverity::High,
                    "hw-dma-fpga",
                    Some(1274),
                    Some(7.6),
                    "dmesg: IOMMU non mentionné; /sys/class/iommu: vide",
                    "Activer Intel VT-d ou AMD-Vi dans le BIOS/UEFI, puis ajouter \
                     intel_iommu=on iommu=force au paramètre kernel dans GRUB.",
                ));
            }
        }

        // Vérifier le mode strict IOMMU
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if !cmdline.contains("iommu=force") && !cmdline.contains("iommu=strict") {
            findings.push(HardwareFinding::new(
                "IOMMU non configuré en mode strict",
                "Le paramètre kernel iommu=force ou iommu=strict n'est pas présent. \
                 En mode lazy (défaut), les mappings DMA peuvent rester valides après \
                 libération, permettant à un device malveillant d'accéder à des zones \
                 mémoire libérées récemment.",
                HwSeverity::Medium,
                "hw-dma-fpga",
                Some(1274),
                Some(5.9),
                &cmdline,
                "Ajouter intel_iommu=on iommu=strict à GRUB_CMDLINE_LINUX dans /etc/default/grub.",
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    findings.push(HardwareFinding::new(
        "Statut IOMMU non vérifiable sur cette plateforme",
        "La vérification IOMMU est disponible uniquement sur Linux. \
         Sur macOS, l'accès DMA est contrôlé par l'architecture Apple Silicon (T2/M-series).",
        HwSeverity::Informative,
        "hw-dma-fpga",
        None, None,
        "plateforme non-Linux",
        "Vérifier la configuration IOMMU/VT-d sur un système Linux.",
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
                let (sev, msg, rem) = match level {
                    "none" => (
                        HwSeverity::Critical,
                        "Thunderbolt niveau sécurité 'none' — DMA sans restriction",
                        "Activer le niveau 'user' ou 'secure' dans le BIOS : \
                         Thunderbolt Security Level → User Authorization",
                    ),
                    "user" => (
                        HwSeverity::Medium,
                        "Thunderbolt niveau 'user' — approbation manuelle requise",
                        "Niveau suffisant pour la plupart des cas. Passer à 'secure' \
                         pour empêcher le DMA pendant le verrouillage.",
                    ),
                    "secure" | "dponly" | "usbonly" => (
                        HwSeverity::Informative,
                        "Thunderbolt niveau sécurisé ('secure'/'dponly'/'usbonly')",
                        "",
                    ),
                    _ => (
                        HwSeverity::Low,
                        "Niveau Thunderbolt inconnu",
                        "Vérifier la configuration Thunderbolt dans le BIOS/UEFI.",
                    ),
                };

                findings.push(HardwareFinding::new(
                    msg,
                    format!("Thunderbolt security level : {}. \
                             Un device Thunderbolt malveillant peut effectuer des accès DMA \
                             si le niveau est 'none' ou si l'IOMMU n'est pas actif.", level),
                    sev,
                    "hw-dma-fpga",
                    Some(284),
                    None,
                    format!("{}: {}", path, level),
                    rem,
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
