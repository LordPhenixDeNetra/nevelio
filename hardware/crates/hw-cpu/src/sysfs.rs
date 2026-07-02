use hw_core::{HardwareFinding, HwSeverity, read_sysfs};
use rust_i18n::t;

const VULN_PATH: &str = "/sys/devices/system/cpu/vulnerabilities";

// Mappage : nom fichier → (CWE, CVSS)
const VULN_MAP: &[(&str, u32, f32)] = &[
    ("spectre_v1",       1342, 5.6),
    ("spectre_v2",       1342, 8.1),
    ("meltdown",         1342, 8.1),
    ("mds",              1342, 6.5),
    ("l1tf",             1342, 6.5),
    ("tsx_async_abort",  1342, 6.5),
    ("retbleed",         1342, 6.5),
    ("spec_store_bypass",1342, 5.5),
    ("mmio_stale_data",  1342, 6.0),
    ("srbds",            1342, 5.5),
];

pub(super) fn check_cpu_vulnerabilities() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    for &(vuln_file, cwe, cvss) in VULN_MAP {
        let path = format!("{}/{}", VULN_PATH, vuln_file);
        let Some(content) = read_sysfs(&path) else { continue };

        if is_vulnerable(&content) {
            let title_key = format!("cpu.vuln.{}.title", vuln_file);
            let rem_key   = format!("cpu.vuln.{}.rem",   vuln_file);
            findings.push(HardwareFinding::new(
                t!(&title_key).to_string(),
                t!("cpu.vuln.desc", content = content.clone()).to_string(),
                severity_for_cvss(cvss),
                "hw-cpu",
                Some(cwe),
                Some(cvss),
                format!("Fichier sysfs `{}` contient : \"{}\"", path, content),
                t!(&rem_key).to_string(),
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
