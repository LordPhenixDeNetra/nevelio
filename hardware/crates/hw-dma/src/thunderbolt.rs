use hw_core::{HardwareFinding, HwSeverity};
use std::fs;

pub(super) fn check_thunderbolt() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let tb_base = "/sys/bus/thunderbolt/devices";
    if !std::path::Path::new(tb_base).exists() {
        return findings; // Pas de Thunderbolt sur cette machine
    }

    let Ok(entries) = fs::read_dir(tb_base) else {
        return findings;
    };

    let mut lowest_security = None::<(String, String)>; // (device, security_level)

    for entry in entries.flatten() {
        let security_path = entry.path().join("security");
        if let Ok(level) = fs::read_to_string(&security_path) {
            let level = level.trim().to_string();
            let device = entry.file_name().to_string_lossy().to_string();

            let rank = security_rank(&level);
            let current_rank = lowest_security.as_ref()
                .map(|(_, l)| security_rank(l))
                .unwrap_or(u8::MAX);

            if rank < current_rank {
                lowest_security = Some((device, level));
            }
        }
    }

    if let Some((device, level)) = lowest_security {
        match level.as_str() {
            "none" => {
                findings.push(HardwareFinding::new(
                    "Thunderbolt Security Level : none — DMA non protégé — CWE-284",
                    "Le niveau de sécurité Thunderbolt est 'none'. N'importe quel \
                     périphérique Thunderbolt/USB4 connecté est automatiquement \
                     autorisé sans confirmation. Un périphérique malveillant peut \
                     effectuer des attaques DMA directes en mémoire (Evil Maid, \
                     Thunderclap, Thunderspy).",
                    HwSeverity::Critical,
                    "hw-dma",
                    Some(284),
                    Some(8.5),
                    format!("Device `{}` : security = \"none\"", device),
                    "Configurer le niveau de sécurité Thunderbolt sur 'user' ou \
                     'secure' dans les paramètres UEFI (Thunderbolt Security Level). \
                     Ou activer IOMMU strict pour limiter l'impact.",
                ));
            }
            "user" => {
                findings.push(HardwareFinding::new(
                    "Thunderbolt Security Level : user — autorisation manuelle requise",
                    "Le niveau de sécurité Thunderbolt est 'user'. Les périphériques \
                     doivent être autorisés manuellement lors de la première connexion. \
                     Une attaque 'Evil Maid' peut exploiter une brève fenêtre \
                     d'inattention ou abuser d'une autorisation préexistante.",
                    HwSeverity::Medium,
                    "hw-dma",
                    Some(284),
                    Some(5.5),
                    format!("Device `{}` : security = \"user\"", device),
                    "Envisager le niveau 'secure' ou 'dponly' pour plus de sécurité. \
                     Activer IOMMU pour limiter les accès DMA même si un périphérique \
                     est autorisé.",
                ));
            }
            "secure" | "dponly" => {
                // Bon niveau de sécurité — informatif
                findings.push(HardwareFinding::new(
                    format!("Thunderbolt Security Level : {} — protégé", level),
                    format!(
                        "Le niveau de sécurité Thunderbolt est '{}'. \
                         Les périphériques sont vérifiés cryptographiquement \
                         avant d'être autorisés.",
                        level
                    ),
                    HwSeverity::Informative,
                    "hw-dma",
                    None,
                    None,
                    format!("Device `{}` : security = \"{}\"", device, level),
                    "Aucune action requise.",
                ));
            }
            other => {
                findings.push(HardwareFinding::new(
                    format!("Thunderbolt Security Level inconnu : {}", other),
                    "Le niveau de sécurité Thunderbolt a une valeur non reconnue.",
                    HwSeverity::Informative,
                    "hw-dma",
                    None,
                    None,
                    format!("Device `{}` : security = \"{}\"", device, other),
                    "Vérifier la documentation noyau Linux pour ce niveau.",
                ));
            }
        }
    }

    findings
}

fn security_rank(level: &str) -> u8 {
    match level {
        "none"    => 0,
        "user"    => 1,
        "secure"  => 2,
        "dponly"  => 3,
        _         => 4,
    }
}
