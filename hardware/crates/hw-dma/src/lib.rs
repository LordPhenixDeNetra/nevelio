use hw_core::{HardwareFinding, HwModule, HwScanContext};

rust_i18n::i18n!("../hw-cli/locales", fallback = "fr");

mod iommu;
mod thunderbolt;
mod pcie;

pub struct DmaModule;

impl HwModule for DmaModule {
    fn name(&self) -> &'static str { "hw-dma" }

    fn description(&self) -> &'static str {
        "Audit de la surface d'attaque DMA : IOMMU, Thunderbolt, PCIe, kernel lockdown"
    }

    fn run(&self, _ctx: &HwScanContext) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();
        findings.extend(iommu::check_iommu());
        findings.extend(thunderbolt::check_thunderbolt());
        findings.extend(pcie::check_pcie_dma());
        findings.extend(check_kernel_lockdown());
        findings
    }
}

fn check_kernel_lockdown() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let path  = "/sys/kernel/security/lockdown";
    let value = hw_core::read_sysfs(path);

    match value.as_deref() {
        Some("none") | None => {
            findings.push(hw_core::HardwareFinding::new(
                "Kernel lockdown inactif — CWE-284",
                "Le kernel lockdown est désactivé ('none') ou le fichier sysfs \
                 est absent. En l'absence de lockdown, un utilisateur root peut \
                 charger des modules non signés, accéder à `/dev/mem`, ou utiliser \
                 debugfs pour lire/modifier la mémoire noyau.",
                hw_core::HwSeverity::Medium,
                "hw-dma",
                Some(284),
                Some(5.3),
                format!(
                    "`{}` = \"{}\"",
                    path,
                    value.as_deref().unwrap_or("fichier absent")
                ),
                "Activer le lockdown noyau en mode 'integrity' ou 'confidentiality' \
                 via le paramètre de démarrage `lockdown=confidentiality`. \
                 Activer Secure Boot active automatiquement lockdown=integrity.",
            ));
        }
        Some("integrity") => {
            findings.push(hw_core::HardwareFinding::new(
                "Kernel lockdown en mode integrity (partiel)",
                "Le lockdown est actif en mode 'integrity' : les modifications \
                 du code noyau en cours d'exécution sont bloquées, mais certains \
                 canaux de fuite d'information restent ouverts (ex: accès raw à \
                 certains périphériques PCI).",
                hw_core::HwSeverity::Informative,
                "hw-dma",
                None,
                None,
                format!("`{}` = \"integrity\"", path),
                "Envisager le passage en mode 'confidentiality' pour une protection \
                 complète : `lockdown=confidentiality` au démarrage.",
            ));
        }
        Some("confidentiality") => {} // Mode le plus strict — OK
        Some(other) => {
            findings.push(hw_core::HardwareFinding::new(
                "Valeur kernel lockdown inconnue",
                format!("La valeur '{}' du kernel lockdown est inconnue.", other),
                hw_core::HwSeverity::Informative,
                "hw-dma",
                None,
                None,
                format!("`{}` = \"{}\"", path, other),
                "Vérifier la documentation noyau pour cette valeur.",
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name() {
        assert_eq!(DmaModule.name(), "hw-dma");
    }
}
