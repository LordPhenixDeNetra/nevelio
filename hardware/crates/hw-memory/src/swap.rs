use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;
#[cfg(target_os = "linux")]
use hw_core::read_sysfs;

/// Vérifie si le swap est chiffré (dm-crypt/LUKS ou swapfs chiffré).
#[cfg(target_os = "linux")]
pub fn check_swap_encryption() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Lire /proc/swaps pour voir les partitions swap actives
    let swaps = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) => s,
        Err(_) => {
            findings.push(HardwareFinding::new(
                t!("memory.swap.inaccessible.title"),
                t!("memory.swap.inaccessible.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "/proc/swaps lecture échouée",
                t!("memory.swap.inaccessible.rem"),
            ));
            return findings;
        }
    };

    // Compter les lignes swap (ignorer le header)
    let swap_partitions: Vec<&str> = swaps
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect();

    if swap_partitions.is_empty() {
        findings.push(HardwareFinding::new(
            t!("memory.swap.none.title"),
            t!("memory.swap.none.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "/proc/swaps : vide (aucune partition swap)",
            t!("memory.swap.none.rem"),
        ));
        return findings;
    }

    // Vérifier si les partitions swap utilisent dm-crypt
    let mut unencrypted = Vec::new();

    for line in &swap_partitions {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }
        let swap_dev = parts[0];

        // dm-crypt apparaît comme /dev/dm-X ou /dev/mapper/...
        let is_encrypted = swap_dev.contains("dm-") || swap_dev.contains("mapper");

        // Vérifier si c'est un device mapper en regardant dans /sys/block/
        let dm_check = if !is_encrypted && swap_dev.starts_with("/dev/") {
            let dev_name = swap_dev.trim_start_matches("/dev/");
            let sysfs_path = format!("/sys/block/{}/dm", dev_name);
            std::path::Path::new(&sysfs_path).exists()
        } else {
            false
        };

        if !is_encrypted && !dm_check {
            unencrypted.push(swap_dev.to_string());
        }
    }

    if unencrypted.is_empty() {
        findings.push(HardwareFinding::new(
            t!("memory.swap.encrypted.title"),
            t!("memory.swap.encrypted.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("{} partition(s) swap — toutes chiffrées", swap_partitions.len()),
            t!("memory.swap.encrypted.rem"),
        ));
    } else {
        let n = unencrypted.len();
        findings.push(HardwareFinding::new(
            t!("memory.swap.unencrypted.title", n = n),
            t!("memory.swap.unencrypted.desc"),
            HwSeverity::High,
            "hw-memory",
            Some(311),
            Some(7.1),
            format!("Swap non chiffré : {}", unencrypted.join(", ")),
            t!("memory.swap.unencrypted.rem"),
        ));
    }

    // Vérifier l'entropie de la clé de chiffrement mémoire (KASLR)
    check_kaslr(&mut findings);

    findings
}

#[cfg(target_os = "linux")]
fn check_kaslr(findings: &mut Vec<HardwareFinding>) {
    // KASLR est activé si randomize_va_space == 2
    if let Some(val) = read_sysfs("/proc/sys/kernel/randomize_va_space") {
        match val.trim() {
            "2" => {
                findings.push(HardwareFinding::new(
                    t!("memory.kaslr.ok.title"),
                    t!("memory.kaslr.ok.desc"),
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    "/proc/sys/kernel/randomize_va_space = 2",
                    t!("memory.kaslr.ok.rem"),
                ));
            }
            "1" => {
                findings.push(HardwareFinding::new(
                    t!("memory.kaslr.partial.title"),
                    t!("memory.kaslr.partial.desc"),
                    HwSeverity::Medium,
                    "hw-memory",
                    Some(330),
                    Some(4.7),
                    "/proc/sys/kernel/randomize_va_space = 1",
                    t!("memory.kaslr.partial.rem"),
                ));
            }
            "0" => {
                findings.push(HardwareFinding::new(
                    t!("memory.kaslr.disabled.title"),
                    t!("memory.kaslr.disabled.desc"),
                    HwSeverity::High,
                    "hw-memory",
                    Some(330),
                    Some(7.8),
                    "/proc/sys/kernel/randomize_va_space = 0",
                    t!("memory.kaslr.disabled.rem"),
                ));
            }
            _ => {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_swap_encryption() -> Vec<HardwareFinding> {
    vec![HardwareFinding::new(
        t!("memory.swap.linux_only.title"),
        t!("memory.swap.linux_only.desc"),
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        format!("OS : {}", std::env::consts::OS),
        t!("memory.swap.linux_only.rem"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_check_does_not_panic() {
        let findings = check_swap_encryption();
        assert!(!findings.is_empty());
    }
}
