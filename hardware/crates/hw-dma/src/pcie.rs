use hw_core::{HardwareFinding, HwSeverity, run_command};

pub(super) fn check_pcie_devices() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(output) = run_command("lspci", &["-v"]) else {
        return findings; // lspci absent — skip silencieux
    };

    findings.extend(check_busmaster_devices(&output));
    findings.extend(check_dangerous_device_classes(&output));

    findings
}

fn check_busmaster_devices(lspci_output: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Compter les devices avec BusMaster activé
    let busmaster_count = lspci_output
        .lines()
        .filter(|l| l.contains("BusMaster"))
        .count();

    if busmaster_count == 0 {
        return findings;
    }

    // Vérifier si des IOMMU groups existent pour isoler ces devices
    let iommu_groups_exist = std::path::Path::new("/sys/kernel/iommu_groups").exists()
        && std::fs::read_dir("/sys/kernel/iommu_groups")
            .map(|d| d.count() > 0)
            .unwrap_or(false);

    if !iommu_groups_exist && busmaster_count > 0 {
        findings.push(HardwareFinding::new(
            format!("{} périphériques PCIe avec BusMaster sans isolation IOMMU", busmaster_count),
            format!(
                "{} périphériques PCIe ont le bit BusMaster activé, ce qui leur permet \
                 d'initier des transactions DMA vers n'importe quelle adresse mémoire. \
                 Sans groupes IOMMU actifs, ces périphériques ne sont pas isolés et \
                 peuvent accéder à toute la RAM de la machine.",
                busmaster_count
            ),
            HwSeverity::High,
            "hw-dma",
            Some(284),
            Some(7.0),
            format!("{} devices avec BusMaster, aucun groupe IOMMU trouvé", busmaster_count),
            "Activer l'IOMMU (intel_iommu=on ou amd_iommu=on) pour isoler les \
             périphériques PCIe dans leurs propres domaines de traduction DMA.",
        ));
    }

    findings
}

fn check_dangerous_device_classes(lspci_output: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Classes PCIe présentant un risque DMA particulier si mal configurées
    let dangerous_classes = [
        ("FireWire", "Firewire/IEEE 1394 — DMA non protégé par défaut sur systèmes anciens"),
        ("ExpressCard", "ExpressCard — extension PCIe directe sans isolation"),
        ("Thunderbolt", "Contrôleur Thunderbolt — voir aussi le check security level"),
    ];

    for (keyword, desc) in &dangerous_classes {
        let matching: Vec<&str> = lspci_output
            .lines()
            .filter(|l| l.to_lowercase().contains(&keyword.to_lowercase()))
            .collect();

        if !matching.is_empty() {
            findings.push(HardwareFinding::new(
                format!("Périphérique PCIe DMA-capable détecté : {}", keyword),
                format!(
                    "{} — Ce type de périphérique peut initier des transactions \
                     DMA vers la RAM. S'assurer qu'il est isolé par IOMMU ou \
                     désactivé si non utilisé.",
                    desc
                ),
                HwSeverity::Low,
                "hw-dma",
                Some(284),
                Some(3.5),
                matching.join("\n"),
                "Activer IOMMU strict. Désactiver dans UEFI les contrôleurs \
                 non utilisés (FireWire, ExpressCard) pour réduire la surface d'attaque.",
            ));
        }
    }

    findings
}
