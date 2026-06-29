use hw_core::{HardwareFinding, HwSeverity};
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
                "/proc/swaps inaccessible",
                "Impossible de lire la liste des partitions swap.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "/proc/swaps lecture échouée",
                "Vérifier les droits de lecture (root requis).",
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
            "Aucun swap actif détecté",
            "Aucune partition ou fichier swap n'est actif. \
             Si le système a de la RAM insuffisante, il peut crasher sans swap. \
             Si intentionnel, c'est acceptable du point de vue sécurité mémoire.",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "/proc/swaps : vide (aucune partition swap)",
            "Si le swap est nécessaire, activer le chiffrement avec dm-crypt.",
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
            "Swap chiffré (dm-crypt/LUKS détecté)",
            "Les partitions swap actives utilisent un device mapper (dm-crypt). \
             Les données en swap sont protégées au repos.",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("{} partition(s) swap — toutes chiffrées", swap_partitions.len()),
            "Maintenir le chiffrement dm-crypt sur toutes les partitions swap.",
        ));
    } else {
        findings.push(HardwareFinding::new(
            format!("Swap non chiffré détecté : {} partition(s) — CWE-311", unencrypted.len()),
            "Des partitions swap non chiffrées sont actives. \
             La mémoire virtuelle peut contenir des secrets (clés, tokens, mots de passe) \
             écrits en clair sur le disque. Une analyse forensique du disque peut les récupérer \
             même après extinction du système.",
            HwSeverity::High,
            "hw-memory",
            Some(311),
            Some(7.1),
            format!("Swap non chiffré : {}", unencrypted.join(", ")),
            "Chiffrer le swap avec dm-crypt :\n\
             1. swapoff <partition>\n\
             2. cryptsetup open --type plain --cipher aes-xts-plain64 <partition> cryptoswap\n\
             3. mkswap /dev/mapper/cryptoswap\n\
             4. swapon /dev/mapper/cryptoswap\n\
             Configurer /etc/crypttab pour la persistance.",
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
                    "KASLR actif (randomize_va_space = 2)",
                    "La randomisation complète des adresses mémoire est activée. \
                     KASLR rend l'exploitation des débordements de tampon significativement plus difficile.",
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    "/proc/sys/kernel/randomize_va_space = 2",
                    "Conserver randomize_va_space = 2 sur tous les systèmes de production.",
                ));
            }
            "1" => {
                findings.push(HardwareFinding::new(
                    "KASLR partiel (randomize_va_space = 1) — CWE-330",
                    "La randomisation des adresses est partielle (pile + VDSO mais pas le tas). \
                     Une randomisation complète (valeur 2) est recommandée.",
                    HwSeverity::Medium,
                    "hw-memory",
                    Some(330),
                    Some(4.7),
                    "/proc/sys/kernel/randomize_va_space = 1",
                    "echo 2 > /proc/sys/kernel/randomize_va_space\n\
                     Ajouter kernel.randomize_va_space = 2 dans /etc/sysctl.conf",
                ));
            }
            "0" => {
                findings.push(HardwareFinding::new(
                    "KASLR désactivé (randomize_va_space = 0) — CWE-330",
                    "La randomisation des adresses mémoire est complètement désactivée. \
                     Les adresses de chargement des bibliothèques, du noyau et de la pile \
                     sont prévisibles, facilitant les attaques ROP/ret2libc.",
                    HwSeverity::High,
                    "hw-memory",
                    Some(330),
                    Some(7.8),
                    "/proc/sys/kernel/randomize_va_space = 0",
                    "Activer immédiatement : echo 2 > /proc/sys/kernel/randomize_va_space\n\
                     Vérifier que aucun outil de debug ne force cette valeur à 0.",
                ));
            }
            _ => {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check_swap_encryption() -> Vec<HardwareFinding> {
    vec![HardwareFinding::new(
        "Vérification swap disponible uniquement sur Linux",
        "L'analyse du chiffrement swap et de KASLR nécessite Linux (/proc/swaps, sysfs).",
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        format!("OS : {}", std::env::consts::OS),
        "Exécuter sur un système Linux pour une analyse complète.",
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
