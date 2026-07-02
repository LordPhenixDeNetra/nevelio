use hw_core::{HardwareFinding, HwSeverity, read_sysfs, run_command};
use rust_i18n::t;

pub(super) fn check_iommu() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // 1. Vérifier les paramètres de démarrage du noyau
    let cmdline = read_sysfs("/proc/cmdline").unwrap_or_default();

    if cmdline.contains("iommu=off") || cmdline.contains("intel_iommu=off") {
        findings.push(HardwareFinding::new(
            t!("dma.iommu.disabled.title").to_string(),
            t!("dma.iommu.disabled.desc").to_string(),
            HwSeverity::Critical,
            "hw-dma",
            Some(284),
            Some(9.0),
            format!("/proc/cmdline : \"{}\"", cmdline.trim()),
            t!("dma.iommu.disabled.rem").to_string(),
        ));
        return findings;
    }

    // 2. Vérifier le mode passthrough
    if cmdline.contains("iommu=pt") {
        findings.push(HardwareFinding::new(
            t!("dma.iommu.passthrough.title").to_string(),
            t!("dma.iommu.passthrough.desc").to_string(),
            HwSeverity::Medium,
            "hw-dma",
            Some(284),
            Some(5.5),
            format!("/proc/cmdline contient 'iommu=pt' : \"{}\"", cmdline.trim()),
            t!("dma.iommu.passthrough.rem").to_string(),
        ));
        return findings;
    }

    // 3. Chercher si l'IOMMU est actif via /sys/kernel/iommu_groups
    let iommu_groups = std::path::Path::new("/sys/kernel/iommu_groups");
    let groups_active = iommu_groups.exists() && {
        std::fs::read_dir(iommu_groups)
            .map(|mut iter| iter.next().is_some())
            .unwrap_or(false)
    };

    if !groups_active {
        // IOMMU non actif — détecter Intel vs AMD pour la remediation
        let is_intel = read_sysfs("/proc/cpuinfo")
            .map(|s| s.contains("GenuineIntel"))
            .unwrap_or(false);

        let remediation = if is_intel {
            t!("dma.iommu.inactive.rem_intel").to_string()
        } else {
            t!("dma.iommu.inactive.rem_amd").to_string()
        };

        findings.push(HardwareFinding {
            title: t!("dma.iommu.inactive.title").to_string(),
            description: t!("dma.iommu.inactive.desc").to_string(),
            severity: HwSeverity::Critical,
            module: "hw-dma".into(),
            cwe: Some(284),
            cvss: Some(9.0),
            evidence: "/sys/kernel/iommu_groups vide ou absent".to_string(),
            remediation,
        });
    }

    findings
}

/// Vérifie si un logger DMESG mentionne l'activation de l'IOMMU
#[allow(dead_code)]
fn iommu_mentioned_in_dmesg() -> bool {
    run_command("dmesg", &["--notime"])
        .map(|out| out.contains("DMAR: IOMMU enabled") || out.contains("AMD-Vi: AMD IOMMUv2"))
        .unwrap_or(false)
}
