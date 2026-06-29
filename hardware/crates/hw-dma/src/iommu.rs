use hw_core::{HardwareFinding, HwSeverity, run_command, read_sysfs};

pub(super) fn check_iommu() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let cmdline = read_sysfs("/proc/cmdline").unwrap_or_default();
    let dmesg   = run_command("dmesg", &[]).unwrap_or_default();

    let intel_iommu_on  = cmdline.contains("intel_iommu=on");
    let amd_iommu_on    = cmdline.contains("amd_iommu=on");
    let iommu_pt        = cmdline.contains("iommu=pt");
    let iommu_off       = cmdline.contains("iommu=off")
                       || cmdline.contains("intel_iommu=off")
                       || cmdline.contains("amd_iommu=off");

    // Détecter le vendor CPU depuis cpuinfo
    let cpuinfo = read_sysfs("/proc/cpuinfo").unwrap_or_default();
    let is_intel = cpuinfo.contains("GenuineIntel");
    let is_amd   = cpuinfo.contains("AuthenticAMD");

    // Vérifier si IOMMU actif via dmesg
    let iommu_active_dmesg = dmesg.contains("IOMMU enabled")
        || dmesg.contains("AMD-Vi: Found IOMMU")
        || dmesg.contains("DMAR: IOMMU enabled")
        || dmesg.contains("iommu: Default domain type: Translated");

    // Vérifier via sysfs si des groupes IOMMU existent
    let iommu_groups_exist = std::path::Path::new("/sys/kernel/iommu_groups").exists()
        && std::fs::read_dir("/sys/kernel/iommu_groups")
            .map(|d| d.count() > 0)
            .unwrap_or(false);

    let iommu_active = (intel_iommu_on || amd_iommu_on || iommu_active_dmesg)
        && !iommu_off
        && iommu_groups_exist;

    if iommu_off {
        findings.push(HardwareFinding::new(
            "IOMMU explicitement désactivé — CWE-284",
            "L'IOMMU est explicitement désactivé via un paramètre noyau (`iommu=off` \
             ou `intel_iommu=off`). Sans IOMMU, tout périphérique DMA-capable \
             (carte réseau, disque NVMe, périphérique Thunderbolt) peut accéder \
             librement à toute la RAM physique de la machine.",
            HwSeverity::Critical,
            "hw-dma",
            Some(284),
            Some(8.5),
            format!("/proc/cmdline : \"{}\"", cmdline.trim()),
            "Supprimer les paramètres `iommu=off` et `intel_iommu=off` du bootloader. \
             Ajouter `intel_iommu=on` (Intel) ou `amd_iommu=on` (AMD) à la place.",
        ));
    } else if !iommu_active {
        let reason = if is_intel && !intel_iommu_on {
            "CPU Intel détecté mais `intel_iommu=on` absent des paramètres noyau"
        } else if is_amd && !amd_iommu_on {
            "CPU AMD détecté mais `amd_iommu=on` absent des paramètres noyau"
        } else {
            "Aucun groupe IOMMU trouvé dans /sys/kernel/iommu_groups"
        };

        findings.push(HardwareFinding::new(
            "IOMMU non actif — risque d'attaque DMA — CWE-284",
            "L'IOMMU (Intel VT-d ou AMD-Vi) ne semble pas actif. Sans IOMMU, \
             un périphérique malveillant connecté (Thunderbolt, PCIe, ExpressCard) \
             peut lire et écrire librement dans toute la RAM via DMA, \
             permettant l'extraction de clés de chiffrement, de mots de passe \
             ou l'injection de code dans le noyau.",
            HwSeverity::High,
            "hw-dma",
            Some(284),
            Some(7.8),
            format!("{}\ndmesg IOMMU : {}", reason, if iommu_active_dmesg { "actif" } else { "absent" }),
            if is_intel {
                "Ajouter `intel_iommu=on iommu=strict` aux paramètres noyau \
                 dans GRUB (`/etc/default/grub`, ligne GRUB_CMDLINE_LINUX). \
                 Activer VT-d dans les paramètres UEFI/BIOS."
            } else {
                "Ajouter `amd_iommu=on iommu=strict` aux paramètres noyau. \
                 Activer AMD-Vi dans les paramètres UEFI/BIOS."
            },
        ));
    } else if iommu_pt {
        // IOMMU en passthrough — moins sécurisé que strict
        findings.push(HardwareFinding::new(
            "IOMMU en mode passthrough — protection DMA réduite",
            "L'IOMMU est actif mais configuré en mode passthrough (`iommu=pt`). \
             Ce mode optimise les performances des VMs mais ne protège pas les \
             périphériques passthrough des attaques DMA. Moins sécurisé que \
             le mode strict.",
            HwSeverity::Low,
            "hw-dma",
            Some(284),
            Some(4.0),
            format!("/proc/cmdline contient `iommu=pt`"),
            "Envisager `iommu=strict` au lieu de `iommu=pt` si la sécurité \
             est prioritaire sur les performances de virtualisation.",
        ));
    }

    findings
}
