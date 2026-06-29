use hw_core::{HardwareFinding, HwSeverity, read_sysfs, run_command};

pub(super) fn check_aslr() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let path  = "/proc/sys/kernel/randomize_va_space";
    let value = read_sysfs(path).unwrap_or_else(|| "unknown".into());

    match value.trim() {
        "2" => {} // ASLR complet — OK
        "1" => {
            findings.push(HardwareFinding::new(
                "ASLR partiel activé (niveau 1)",
                "ASLR est activé en mode partiel (niveau 1) : seuls le stack et les \
                 bibliothèques partagées sont randomisés. Le heap n'est pas randomisé, \
                 ce qui facilite les attaques heap spray.",
                HwSeverity::Medium,
                "hw-cpu",
                Some(119),
                Some(5.5),
                format!("`{}` = \"{}\"", path, value),
                "Définir `kernel.randomize_va_space = 2` dans `/etc/sysctl.conf` \
                 puis exécuter `sysctl -p`.",
            ));
        }
        "0" => {
            findings.push(HardwareFinding::new(
                "ASLR désactivé — CWE-119",
                "L'Address Space Layout Randomization (ASLR) est complètement désactivé. \
                 Les adresses mémoire sont prévisibles, ce qui facilite les exploits \
                 de type buffer overflow, ROP chains et heap spray.",
                HwSeverity::High,
                "hw-cpu",
                Some(119),
                Some(7.0),
                format!("`{}` = \"{}\"", path, value),
                "Activer ASLR complet : `echo 2 > /proc/sys/kernel/randomize_va_space` \
                 et persister via `sysctl kernel.randomize_va_space=2`.",
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
                    "KASLR — /proc/kallsyms expose les adresses noyau",
                    "Le fichier `/proc/kallsyms` est lisible par un utilisateur non-root \
                     et révèle les adresses réelles des symboles noyau. Un attaquant local \
                     peut contourner KASLR sans droits élevés.",
                    HwSeverity::High,
                    "hw-cpu",
                    Some(200),
                    Some(6.5),
                    format!("Première entrée kallsyms : `{}`", first_line),
                    "Restreindre l'accès : `echo 2 > /proc/sys/kernel/kptr_restrict` \
                     et persister via `sysctl kernel.kptr_restrict=2`.",
                ));
            }
        }
    }

    // Vérifier kptr_restrict directement
    let kptr = read_sysfs("/proc/sys/kernel/kptr_restrict")
        .unwrap_or_else(|| "unknown".into());
    if kptr == "0" {
        findings.push(HardwareFinding::new(
            "kptr_restrict désactivé — adresses pointeurs noyau exposées",
            "`kptr_restrict = 0` permet à tout utilisateur de lire les adresses \
             des pointeurs noyau via `/proc/kallsyms`, `/proc/modules` et d'autres \
             interfaces. Facilite les exploits d'élévation de privilèges.",
            HwSeverity::Medium,
            "hw-cpu",
            Some(200),
            Some(5.5),
            format!("`/proc/sys/kernel/kptr_restrict` = \"{}\"", kptr),
            "Définir `kernel.kptr_restrict = 2` dans `/etc/sysctl.conf`.",
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
                        "dmesg expose des adresses mémoire noyau",
                        "`dmesg_restrict = 0` et dmesg contient des adresses mémoire \
                         noyau lisibles sans droits élevés. Ces adresses facilitent \
                         le contournement de KASLR.",
                        HwSeverity::Low,
                        "hw-cpu",
                        Some(200),
                        Some(3.5),
                        "dmesg contient des adresses de la forme 0xffff...",
                        "Définir `kernel.dmesg_restrict = 1` dans `/etc/sysctl.conf`.",
                    ));
                }
            }
        }
    }

    findings
}
