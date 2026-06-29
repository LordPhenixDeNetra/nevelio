use hw_core::{HardwareFinding, HwSeverity, run_command, read_sysfs};

pub(super) fn check_microcode() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    findings.extend(check_microcode_version());
    findings.extend(check_cpu_flags());
    findings
}

fn check_microcode_version() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // /proc/cpuinfo contient la version microcode sur les CPU Intel/AMD
    let cpuinfo = read_sysfs("/proc/cpuinfo").unwrap_or_default();

    let microcode_version = cpuinfo
        .lines()
        .find(|l| l.starts_with("microcode"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string());

    let vendor = cpuinfo
        .lines()
        .find(|l| l.starts_with("vendor_id"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    let model_name = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    match &microcode_version {
        None => {
            findings.push(HardwareFinding::new(
                "Version microcode CPU non lisible",
                "La version du microcode CPU n'a pas pu être lue depuis `/proc/cpuinfo`. \
                 Il est impossible de vérifier si le microcode est à jour pour les \
                 mitigations Spectre/Meltdown/MDS.",
                HwSeverity::Informative,
                "hw-cpu",
                None,
                None,
                "Champ 'microcode' absent de /proc/cpuinfo",
                "Vérifier manuellement avec `dmidecode -t processor` (root requis) \
                 ou `rdmsr 0x8b` (msr-tools).",
            ));
        }
        Some(version) => {
            // Vérifier si le microcode est chargé au démarrage via initrd
            let microcode_loaded = check_early_microcode_load(&cpuinfo);
            if !microcode_loaded {
                findings.push(HardwareFinding::new(
                    "Microcode CPU chargé tardivement (pas d'early load)",
                    "Le microcode CPU n'est pas chargé en early initramfs. Il est chargé \
                     tardivement par le système, ce qui signifie que le noyau démarre \
                     sans les derniers correctifs microcode pendant quelques secondes.",
                    HwSeverity::Low,
                    "hw-cpu",
                    Some(1395),
                    Some(3.0),
                    format!("CPU : {} | Microcode : {}", model_name, version),
                    "Installer le paquet `intel-microcode` ou `amd64-microcode` \
                     et reconstruire l'initramfs : `update-initramfs -u`.",
                ));
            }

            // Avertissement si le vendor est Intel et microcode potentiellement vieux
            // (heuristique simple — pas de base de données complète embarquée)
            if vendor.contains("Intel") {
                check_intel_speculative_vuln(&cpuinfo, &mut findings);
            }
        }
    }

    findings
}

fn check_early_microcode_load(_cpuinfo: &str) -> bool {
    // Sur Linux, /proc/cpuinfo indique "microcode" chargé depuis initrd
    // via dmesg. Vérification indirecte : chercher dans dmesg.
    if let Some(dmesg) = run_command("dmesg", &[]) {
        if dmesg.contains("microcode updated early") ||
           dmesg.contains("microcode: updated to revision") {
            return true;
        }
        // Certains kernels log différemment
        if dmesg.contains("microcode: CPU") && dmesg.contains("updated") {
            return true;
        }
    }
    // /sys/devices/system/cpu/microcode/reload existe si le module est chargé
    std::path::Path::new("/sys/devices/system/cpu/microcode/reload").exists()
}

fn check_intel_speculative_vuln(cpuinfo: &str, findings: &mut Vec<HardwareFinding>) {
    // Vérifier si l'Enhanced IBRS (EIBRS) est supporté — meilleure mitigation
    let has_eibrs = cpuinfo.contains("ibrs_enhanced") || cpuinfo.contains("arch_capabilities");
    if !has_eibrs {
        // CPU Intel sans EIBRS — nécessite retpolines + IBRS logiciel (plus lent)
        let cpu_family = extract_cpu_field(cpuinfo, "cpu family")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let model = extract_cpu_field(cpuinfo, "model")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        // Famille 6, modèles < 78 (Skylake+) → pas d'EIBRS natif
        if cpu_family == 6 && model < 78 {
            findings.push(HardwareFinding::new(
                "CPU Intel sans Enhanced IBRS — mitigation Spectre v2 moins efficace",
                "Ce processeur Intel ne supporte pas Enhanced IBRS (EIBRS). \
                 La mitigation Spectre v2 repose sur des retpolines logicielles \
                 qui ont un coût performance plus élevé et couvrent moins de cas.",
                HwSeverity::Low,
                "hw-cpu",
                Some(1342),
                Some(4.0),
                format!("CPU family: {}, model: {} — EIBRS non supporté", cpu_family, model),
                "Envisager la mise à niveau vers une génération CPU supportant EIBRS \
                 (Intel Cascade Lake ou ultérieur, famille 6 modèle ≥ 85).",
            ));
        }
    }
}

fn check_cpu_flags() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    let cpuinfo = read_sysfs("/proc/cpuinfo").unwrap_or_default();

    // NX/XD bit — prévention d'exécution de données
    if !cpuinfo.contains(" nx ") && !cpuinfo.contains(" xd ") {
        findings.push(HardwareFinding::new(
            "Bit NX/XD (No-Execute) absent des flags CPU",
            "Le flag NX (Intel XD) n'est pas présent dans `/proc/cpuinfo`. \
             Ce bit permet au CPU de marquer des pages mémoire comme non-exécutables, \
             bloquant les attaques de type shellcode classiques.",
            HwSeverity::High,
            "hw-cpu",
            Some(284),
            Some(7.0),
            "Flags CPU depuis /proc/cpuinfo ne contiennent pas 'nx' ou 'xd'",
            "Activer le bit NX/XD dans les paramètres BIOS/UEFI (souvent appelé \
             'Execute Disable Bit', 'XD Technology', ou 'No Execute Memory Protect').",
        ));
    }

    // SME/SEV (AMD Secure Memory Encryption) — informatif si absent
    // SMEP/SMAP — supervisor mode execution/access prevention
    if !cpuinfo.contains(" smep ") {
        findings.push(HardwareFinding::new(
            "SMEP (Supervisor Mode Execution Prevention) non supporté",
            "SMEP empêche le noyau d'exécuter du code situé dans les pages utilisateur. \
             Sans SMEP, un exploit noyau peut rediriger l'exécution vers du shellcode \
             placé dans l'espace utilisateur.",
            HwSeverity::Medium,
            "hw-cpu",
            Some(284),
            Some(5.5),
            "Flag 'smep' absent de /proc/cpuinfo",
            "SMEP est une fonctionnalité hardware (Intel Ivy Bridge+ / AMD Excavator+). \
             Si le CPU ne le supporte pas, envisager une mise à niveau matérielle.",
        ));
    }

    findings
}

fn extract_cpu_field<'a>(cpuinfo: &'a str, field: &str) -> Option<String> {
    cpuinfo
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cpu_field_works() {
        let cpuinfo = "cpu family\t: 6\nmodel\t: 142\nmodel name\t: Intel Core i7";
        assert_eq!(extract_cpu_field(cpuinfo, "cpu family"), Some("6".into()));
        assert_eq!(extract_cpu_field(cpuinfo, "model name"), Some("Intel Core i7".into()));
        assert_eq!(extract_cpu_field(cpuinfo, "unknown"), None);
    }
}
