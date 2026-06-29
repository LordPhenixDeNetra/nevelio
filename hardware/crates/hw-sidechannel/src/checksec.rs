use hw_core::{run_command, HardwareFinding, HwSeverity};

/// Vérifie les protections stack/binaire via checksec et /proc/sys.
pub fn check_stack_protections() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    findings.extend(check_aslr_entropy());
    findings.extend(check_checksec_kernel());
    findings.extend(check_ptrace_scope());

    findings
}

/// Vérifie l'entropie ASLR (/proc/sys/kernel/perf_event_paranoid est proxied).
fn check_aslr_entropy() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // bits d'entropie ASLR pour mmap (Linux-specific)
    let mmap_bits  = hw_core::read_sysfs("/proc/sys/vm/mmap_rnd_bits");
    let mmap_bits32 = hw_core::read_sysfs("/proc/sys/vm/mmap_rnd_compat_bits");

    match mmap_bits.as_deref() {
        None => {} // Non-Linux : skip silencieusement
        Some(val) => {
            let bits: u32 = val.parse().unwrap_or(0);
            if bits < 28 {
                findings.push(HardwareFinding::new(
                    "Entropie ASLR mmap insuffisante (CWE-330)",
                    format!(
                        "mmap_rnd_bits = {} < 28 bits. Une entropie faible rend \
                         l'ASLR bruteforçable en quelques milliers de tentatives. \
                         La valeur recommandée est ≥ 32 bits.",
                        bits
                    ),
                    HwSeverity::Medium,
                    "hw-sidechannel",
                    Some(330),
                    Some(5.3),
                    format!("/proc/sys/vm/mmap_rnd_bits = {}", val),
                    "echo 32 > /proc/sys/vm/mmap_rnd_bits\n\
                     Ou dans /etc/sysctl.d/99-hardening.conf :\n\
                     vm.mmap_rnd_bits = 32",
                ));
            }
        }
    }

    if let Some(val32) = mmap_bits32 {
        let bits: u32 = val32.parse().unwrap_or(0);
        if bits < 16 {
            findings.push(HardwareFinding::new(
                "Entropie ASLR compat 32-bit insuffisante (CWE-330)",
                format!(
                    "mmap_rnd_compat_bits = {} < 16 bits. Les processus 32-bit \
                     émulés ont une entropie ASLR très faible.",
                    bits
                ),
                HwSeverity::Low,
                "hw-sidechannel",
                Some(330),
                Some(3.7),
                format!("/proc/sys/vm/mmap_rnd_compat_bits = {}", val32),
                "echo 16 > /proc/sys/vm/mmap_rnd_compat_bits",
            ));
        }
    }

    findings
}

/// Vérifie les paramètres sysctl de protection via checksec.sh ou sysctl direct.
fn check_checksec_kernel() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // perf_event_paranoid : contrôle l'accès aux compteurs de performance
    // Valeur -1 = tout accessible, 0 = accessible, 1 = partiel, 2 = root only, 3 = désactivé
    match hw_core::read_sysfs("/proc/sys/kernel/perf_event_paranoid").as_deref() {
        Some(val) => {
            let v: i32 = val.parse().unwrap_or(0);
            if v < 2 {
                findings.push(HardwareFinding::new(
                    "perf_event_paranoid trop permissif — side-channel PMU possible (CWE-1342)",
                    format!(
                        "perf_event_paranoid = {} permet à un utilisateur non-root d'accéder \
                         aux compteurs de performance matérielle (PMU). Ces compteurs peuvent \
                         être exploités pour des attaques side-channel (Spectre, cache timing).",
                        v
                    ),
                    HwSeverity::Medium,
                    "hw-sidechannel",
                    Some(1342),
                    Some(5.5),
                    format!("/proc/sys/kernel/perf_event_paranoid = {}", val),
                    "echo 3 > /proc/sys/kernel/perf_event_paranoid\n\
                     Ou dans sysctl.conf : kernel.perf_event_paranoid = 3\n\
                     Note : cela désactive perf pour les non-root.",
                ));
            } else {
                findings.push(HardwareFinding::new(
                    "perf_event_paranoid correctement configuré",
                    format!("Valeur {} ≥ 2 : accès PMU restreint aux utilisateurs root.", v),
                    HwSeverity::Informative,
                    "hw-sidechannel",
                    None, None,
                    format!("/proc/sys/kernel/perf_event_paranoid = {}", val),
                    "Configuration optimale : 3 pour désactiver complètement l'accès PMU non-root.",
                ));
            }
        }
        None => {} // Non-Linux
    }

    // Vérifier via checksec si disponible
    if let Some(output) = run_command("checksec", &["--kernel"]) {
        analyze_checksec_kernel_output(&output, &mut findings);
    }

    findings
}

fn analyze_checksec_kernel_output(output: &str, findings: &mut Vec<HardwareFinding>) {
    // checksec --kernel affiche des lignes comme :
    // [*] SMEP: ENABLED
    // [*] SMAP: ENABLED
    // [*] GCC stack protector support: ENABLED
    for line in output.lines() {
        let line = line.trim();
        if line.contains("SMEP") && line.contains("DISABLED") {
            findings.push(HardwareFinding::new(
                "SMEP désactivé (checksec)",
                "Supervisor Mode Execution Prevention (SMEP) est désactivé. \
                 SMEP empêche le noyau d'exécuter du code en espace utilisateur.",
                HwSeverity::High,
                "hw-sidechannel",
                Some(1342),
                Some(7.0),
                line.to_string(),
                "Activer SMEP en ajoutant `smep` dans les options du noyau. \
                 Vérifier que le BIOS/UEFI ne le désactive pas.",
            ));
        }
        if line.contains("SMAP") && line.contains("DISABLED") {
            findings.push(HardwareFinding::new(
                "SMAP désactivé (checksec)",
                "Supervisor Mode Access Prevention (SMAP) est désactivé. \
                 SMAP empêche le noyau d'accéder accidentellement à l'espace utilisateur.",
                HwSeverity::Medium,
                "hw-sidechannel",
                Some(1342),
                Some(5.5),
                line.to_string(),
                "Activer SMAP via les options du noyau (`smap`). \
                 Nécessite un CPU Intel Broadwell+ ou AMD Zen+.",
            ));
        }
    }
}

fn check_ptrace_scope() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    match hw_core::read_sysfs("/proc/sys/kernel/yama/ptrace_scope").as_deref() {
        None => {} // Yama non disponible
        Some("0") => {
            findings.push(HardwareFinding::new(
                "ptrace sans restriction — injection de processus possible (CWE-862)",
                "ptrace_scope = 0 permet à tout utilisateur de tracer n'importe quel \
                 processus lui appartenant. Un attaquant ayant un shell peut injecter \
                 du code dans d'autres processus (ex: navigateur, client GPG).",
                HwSeverity::Medium,
                "hw-sidechannel",
                Some(862),
                Some(5.5),
                "/proc/sys/kernel/yama/ptrace_scope = 0",
                "echo 1 > /proc/sys/kernel/yama/ptrace_scope\n\
                 Ou sysctl kernel.yama.ptrace_scope = 1\n\
                 Valeur 1 = seul le parent peut tracer ses enfants.\n\
                 Valeur 3 = ptrace totalement désactivé (recommandé en production).",
            ));
        }
        Some("1") => {
            findings.push(HardwareFinding::new(
                "ptrace_scope = 1 (restrictions partielles)",
                "Seul le processus parent peut tracer ses enfants. \
                 Protection suffisante pour la plupart des cas mais non optimale.",
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                "/proc/sys/kernel/yama/ptrace_scope = 1",
                "Envisager la valeur 3 pour désactiver ptrace en production.",
            ));
        }
        Some(v @ "2") | Some(v @ "3") => {
            findings.push(HardwareFinding::new(
                "ptrace_scope correctement restreint",
                format!("ptrace_scope = {} : seul root ou les processus avec CAP_SYS_PTRACE peuvent tracer.", v),
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                format!("/proc/sys/kernel/yama/ptrace_scope = {}", v),
                "Configuration optimale.",
            ));
        }
        Some(v) => {
            findings.push(HardwareFinding::new(
                "ptrace_scope : valeur inconnue",
                format!("Valeur inattendue : {}", v),
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                format!("/proc/sys/kernel/yama/ptrace_scope = {}", v),
                "Vérifier la documentation Yama LSM.",
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_stack_does_not_panic() {
        let _ = check_stack_protections();
    }

    #[test]
    fn analyze_checksec_smep_disabled() {
        let output = "[*] SMEP: DISABLED\n[*] SMAP: ENABLED\n";
        let mut findings = Vec::new();
        analyze_checksec_kernel_output(output, &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("SMEP")));
    }
}
