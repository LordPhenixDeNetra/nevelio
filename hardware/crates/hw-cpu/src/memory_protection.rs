use hw_core::{HardwareFinding, HwSeverity, read_sysfs, run_command};
use rust_i18n::t;

pub(super) fn check_aslr() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let path  = "/proc/sys/kernel/randomize_va_space";
    let value = read_sysfs(path).unwrap_or_else(|| "unknown".into());

    match value.trim() {
        "2" => {} // ASLR complet — OK
        "1" => {
            findings.push(HardwareFinding::new(
                t!("cpu.aslr.partial.title").to_string(),
                t!("cpu.aslr.partial.desc").to_string(),
                HwSeverity::Medium,
                "hw-cpu",
                Some(119),
                Some(5.5),
                format!("`{}` = \"{}\"", path, value),
                t!("cpu.aslr.partial.rem").to_string(),
            ));
        }
        "0" => {
            findings.push(HardwareFinding::new(
                t!("cpu.aslr.disabled.title").to_string(),
                t!("cpu.aslr.disabled.desc").to_string(),
                HwSeverity::High,
                "hw-cpu",
                Some(119),
                Some(7.0),
                format!("`{}` = \"{}\"", path, value),
                t!("cpu.aslr.disabled.rem").to_string(),
            ));
        }
        _ => {
            // Fichier illisible ou valeur inconnue (non-Linux, VM légère, etc.)
        }
    }

    findings
}

pub(super) fn check_kaslr() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // /proc/kallsyms expose les adresses du noyau si lisible par un utilisateur non-root.
    // Normalement les adresses sont masquées (affichées comme 0000000000000000).
    if let Some(content) = read_sysfs("/proc/kallsyms") {
        let first_line = content.lines().next().unwrap_or("");
        // Si la première adresse n'est pas zéro → KASLR inefficace ou désactivé
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if let Some(addr) = parts.first() {
            let all_zeros = addr.chars().all(|c| c == '0');
            if !all_zeros && addr.len() >= 16 {
                findings.push(HardwareFinding::new(
                    t!("cpu.kaslr.kallsyms_exposed.title").to_string(),
                    t!("cpu.kaslr.kallsyms_exposed.desc").to_string(),
                    HwSeverity::High,
                    "hw-cpu",
                    Some(200),
                    Some(6.5),
                    format!("Première entrée kallsyms : `{}`", first_line),
                    t!("cpu.kaslr.kallsyms_exposed.rem").to_string(),
                ));
            }
        }
    }

    // Vérifier kptr_restrict directement
    let kptr = read_sysfs("/proc/sys/kernel/kptr_restrict")
        .unwrap_or_else(|| "unknown".into());
    if kptr == "0" {
        findings.push(HardwareFinding::new(
            t!("cpu.kaslr.kptr_disabled.title").to_string(),
            t!("cpu.kaslr.kptr_disabled.desc").to_string(),
            HwSeverity::Medium,
            "hw-cpu",
            Some(200),
            Some(5.5),
            format!("`/proc/sys/kernel/kptr_restrict` = \"{}\"", kptr),
            t!("cpu.kaslr.kptr_disabled.rem").to_string(),
        ));
    }

    // Vérifier dmesg_restrict
    if let Some(dmesg) = read_sysfs("/proc/sys/kernel/dmesg_restrict") {
        if dmesg == "0" {
            // Vérifier si dmesg contient des adresses noyau
            if let Some(dmesg_out) = run_command("dmesg", &["--notime", "-l", "notice"]) {
                let has_addresses = dmesg_out.lines().any(|l| {
                    l.contains("0xffff") || l.contains("[<ffff")
                });
                if has_addresses {
                    findings.push(HardwareFinding::new(
                        t!("cpu.kaslr.dmesg_exposes.title").to_string(),
                        t!("cpu.kaslr.dmesg_exposes.desc").to_string(),
                        HwSeverity::Low,
                        "hw-cpu",
                        Some(200),
                        Some(3.5),
                        "dmesg contient des adresses de la forme 0xffff...",
                        t!("cpu.kaslr.dmesg_exposes.rem").to_string(),
                    ));
                }
            }
        }
    }

    findings
}
