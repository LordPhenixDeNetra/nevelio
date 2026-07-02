use hw_core::{HardwareFinding, HwSeverity, run_command};
use rust_i18n::t;

// Classes PCIe avec capacité DMA potentiellement dangereuses
const DMA_CAPABLE_CLASSES: &[(&str, &str)] = &[
    ("0c0a", "Thunderbolt"),
    ("0c03", "USB3.0 xHCI"),
    ("0c00", "FireWire (IEEE 1394)"),
    ("0604", "PCIe Bridge"),
    ("0200", "Ethernet controller"),
    ("0280", "Network controller Wi-Fi"),
    ("0108", "NVMe Storage"),
    ("0106", "SATA AHCI"),
];

pub(super) fn check_pcie_dma() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(lspci_output) = run_command("lspci", &["-v"]) else {
        return findings;
    };

    // Vérifier si l'IOMMU est actif
    let iommu_groups_active = std::path::Path::new("/sys/kernel/iommu_groups")
        .read_dir()
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);

    // Compter les périphériques avec BusMaster activé
    let busmaster_count = lspci_output
        .lines()
        .filter(|l| l.contains("BusMaster+"))
        .count();

    if busmaster_count > 0 && !iommu_groups_active {
        findings.push(HardwareFinding::new(
            t!("dma.pcie.busmaster_no_iommu.title", count = busmaster_count.to_string()).to_string(),
            t!("dma.pcie.busmaster_no_iommu.desc", count = busmaster_count.to_string()).to_string(),
            HwSeverity::High,
            "hw-dma",
            Some(284),
            Some(7.0),
            format!("{} périphériques PCIe avec BusMaster détectés (IOMMU inactif)", busmaster_count),
            t!("dma.pcie.busmaster_no_iommu.rem").to_string(),
        ));
    }

    // Rechercher des classes DMA dangereuses
    for (class_id, desc) in DMA_CAPABLE_CLASSES {
        // lspci -n affiche les IDs de classe ; on cherche dans la sortie verbose
        let keyword = desc.to_lowercase();
        let matches: Vec<&str> = lspci_output
            .lines()
            .filter(|l| l.to_lowercase().contains(&keyword))
            .collect();

        if !matches.is_empty() {
            let evidence = matches.first().copied().unwrap_or("").to_string();
            findings.push(HardwareFinding::new(
                t!("dma.pcie.dma_capable.title", keyword = desc.to_string()).to_string(),
                t!("dma.pcie.dma_capable.desc", keyword = desc.to_string(), desc = format!("(classe {:04})", class_id)).to_string(),
                HwSeverity::Informative,
                "hw-dma",
                Some(284),
                Some(4.0),
                evidence,
                t!("dma.pcie.dma_capable.rem").to_string(),
            ));
        }
    }

    findings
}
