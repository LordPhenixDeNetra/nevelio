use hw_core::{HardwareFinding, HwSeverity, read_sysfs};

const VULN_PATH: &str = "/sys/devices/system/cpu/vulnerabilities";

// Mappage : nom fichier → (titre, CWE, CVSS si vulnérable, remédiation)
const VULN_MAP: &[(&str, &str, u32, f32, &str)] = &[
    (
        "spectre_v1",
        "Spectre v1 — Bounds Check Bypass",
        1342, 5.6,
        "Mettre à jour le microcode CPU et le noyau Linux. Appliquer les patches SWAPGS \
         et usercopy barriers. Vérifier que le noyau est ≥ 5.2.",
    ),
    (
        "spectre_v2",
        "Spectre v2 — Branch Target Injection",
        1342, 8.1,
        "Activer IBRS/IBPB/STIBP via le microcode Intel/AMD à jour. Vérifier \
         `/sys/devices/system/cpu/vulnerabilities/spectre_v2` affiche 'Mitigation: Retpolines'.",
    ),
    (
        "meltdown",
        "Meltdown — Rogue Data Cache Load",
        1342, 8.1,
        "Activer KPTI (Kernel Page-Table Isolation). Mettre à jour le noyau Linux ≥ 4.15. \
         Vérifier `/proc/cpuinfo` contient le flag 'pti'.",
    ),
    (
        "mds",
        "MDS — Microarchitectural Data Sampling",
        1342, 6.5,
        "Mettre à jour le microcode Intel (mai 2019 ou ultérieur). Activer le vidage \
         des buffers CPU via 'mds=full,nosmt' dans les paramètres noyau.",
    ),
    (
        "l1tf",
        "L1TF — L1 Terminal Fault",
        1342, 6.5,
        "Appliquer le microcode Intel août 2018. Activer 'l1tf=full,force' dans les \
         paramètres noyau. Désactiver Hyper-Threading si risque élevé.",
    ),
    (
        "tsx_async_abort",
        "TAA — TSX Asynchronous Abort",
        1342, 6.5,
        "Mettre à jour le microcode Intel (novembre 2019). Désactiver TSX via \
         'tsx=off' si le microcode n'est pas disponible.",
    ),
    (
        "retbleed",
        "Retbleed — Return Stack Buffer Underflow",
        1342, 6.5,
        "Mettre à jour le noyau Linux ≥ 5.19. Appliquer les patches Retbleed \
         (IBPB-on-entry ou SRSO pour AMD).",
    ),
    (
        "spec_store_bypass",
        "Spectre v4 — Speculative Store Bypass",
        1342, 5.5,
        "Activer SSBD (Speculative Store Bypass Disable) via le microcode et \
         le paramètre noyau 'spec_store_bypass_disable=seccomp'.",
    ),
    (
        "mmio_stale_data",
        "MMIO Stale Data — Intel MMIO Information Disclosure",
        1342, 6.0,
        "Mettre à jour le microcode Intel (juin 2022). Appliquer les patches \
         noyau MMIO Stale Data (Linux ≥ 5.18).",
    ),
    (
        "srbds",
        "SRBDS — Special Register Buffer Data Sampling",
        1342, 5.5,
        "Mettre à jour le microcode Intel (juin 2020). Vérifier que \
         `/sys/devices/system/cpu/vulnerabilities/srbds` affiche 'Mitigation'.",
    ),
];

pub(super) fn check_cpu_vulnerabilities() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    for &(vuln_file, title, cwe, cvss, remediation) in VULN_MAP {
        let path = format!("{}/{}", VULN_PATH, vuln_file);
        let Some(content) = read_sysfs(&path) else { continue };

        if is_vulnerable(&content) {
            findings.push(HardwareFinding::new(
                title,
                format!(
                    "Le noyau Linux rapporte une vulnérabilité CPU non atténuée : {}",
                    content
                ),
                severity_for_cvss(cvss),
                "hw-cpu",
                Some(cwe),
                Some(cvss),
                format!("Fichier sysfs `{}` contient : \"{}\"", path, content),
                remediation,
            ));
        }
    }

    findings
}

fn is_vulnerable(content: &str) -> bool {
    let lower = content.to_lowercase();
    // "Vulnerable" sans mitigation mentionnée → finding
    // "Not affected" ou "Mitigation: ..." → OK
    lower.contains("vulnerable") && !lower.contains("mitigation")
}

fn severity_for_cvss(cvss: f32) -> HwSeverity {
    match cvss as u32 {
        9..=10 => HwSeverity::Critical,
        7..=8  => HwSeverity::High,
        4..=6  => HwSeverity::Medium,
        1..=3  => HwSeverity::Low,
        _      => HwSeverity::Informative,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vulnerable_detection() {
        assert!(is_vulnerable("Vulnerable"));
        assert!(is_vulnerable("Vulnerable: Unprivileged eBPF enabled"));
        assert!(!is_vulnerable("Not affected"));
        assert!(!is_vulnerable("Mitigation: Retpolines"));
        assert!(!is_vulnerable("Mitigation: usercopy/swapgs barriers"));
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(severity_for_cvss(9.0), HwSeverity::Critical);
        assert_eq!(severity_for_cvss(8.1), HwSeverity::High);
        assert_eq!(severity_for_cvss(6.5), HwSeverity::Medium);
        assert_eq!(severity_for_cvss(2.0), HwSeverity::Low);
    }
}
