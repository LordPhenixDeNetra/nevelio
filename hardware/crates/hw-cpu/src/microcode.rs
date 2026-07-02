use hw_core::{HardwareFinding, HwSeverity, run_command, read_sysfs};
use rust_i18n::t;

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
                t!("cpu.microcode.not_readable.title").to_string(),
                t!("cpu.microcode.not_readable.desc").to_string(),
                HwSeverity::Informative,
                "hw-cpu",
                None,
                None,
                "Champ 'microcode' absent de /proc/cpuinfo",
                t!("cpu.microcode.not_readable.rem").to_string(),
            ));
        }
        Some(version) => {
            // Vérifier si le microcode est chargé au démarrage via initrd
            let microcode_loaded = check_early_microcode_load(&cpuinfo);
            if !microcode_loaded {
                findings.push(HardwareFinding::new(
                    t!("cpu.microcode.late_load.title").to_string(),
                    t!("cpu.microcode.late_load.desc").to_string(),
                    HwSeverity::Low,
                    "hw-cpu",
                    Some(1395),
                    Some(3.0),
                    format!("CPU : {} | Microcode : {}", model_name, version),
                    t!("cpu.microcode.late_load.rem").to_string(),
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
                t!("cpu.microcode.no_eibrs.title").to_string(),
                t!("cpu.microcode.no_eibrs.desc").to_string(),
                HwSeverity::Low,
                "hw-cpu",
                Some(1342),
                Some(4.0),
                format!("CPU family: {}, model: {} — EIBRS non supporté", cpu_family, model),
                t!("cpu.microcode.no_eibrs.rem").to_string(),
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
            t!("cpu.flags.no_nx.title").to_string(),
            t!("cpu.flags.no_nx.desc").to_string(),
            HwSeverity::High,
            "hw-cpu",
            Some(284),
            Some(7.0),
            "Flags CPU depuis /proc/cpuinfo ne contiennent pas 'nx' ou 'xd'",
            t!("cpu.flags.no_nx.rem").to_string(),
        ));
    }

    // SME/SEV (AMD Secure Memory Encryption) — informatif si absent
    // SMEP/SMAP — supervisor mode execution/access prevention
    if !cpuinfo.contains(" smep ") {
        findings.push(HardwareFinding::new(
            t!("cpu.flags.no_smep.title").to_string(),
            t!("cpu.flags.no_smep.desc").to_string(),
            HwSeverity::Medium,
            "hw-cpu",
            Some(284),
            Some(5.5),
            "Flag 'smep' absent de /proc/cpuinfo",
            t!("cpu.flags.no_smep.rem").to_string(),
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
