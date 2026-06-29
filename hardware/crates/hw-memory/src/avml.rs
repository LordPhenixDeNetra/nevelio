use hw_core::{run_command, HardwareFinding, HwSeverity};
use std::path::Path;

const AVML_OUTPUT: &str = "/tmp/nevelio_memory.lime";
#[cfg(target_os = "linux")]
const LIME_MODULE: &str = "/tmp/lime.ko";

/// Vérifie si avml (Azure Volatile Memory Library) est installé.
pub fn detect_avml() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let avml_present = run_command("which", &["avml"]).map_or(false, |o| !o.trim().is_empty());

    if avml_present {
        findings.push(HardwareFinding::new(
            "avml (outil de dump mémoire) détecté",
            "avml est présent sur le système. Cet outil permet de dumper la RAM physique \
             complète en espace utilisateur (sans module noyau). \
             Si présent sur un système de production sans justification, \
             il peut indiquer une compromission ou une opération forensique non autorisée.",
            HwSeverity::Medium,
            "hw-memory",
            Some(1342),
            Some(5.5),
            "which avml → trouvé",
            "Sur les systèmes de production, avml ne devrait pas être installé. \
             Utiliser un contrôle d'intégrité (AIDE, auditd) pour détecter son installation.",
        ));
    } else {
        findings.push(HardwareFinding::new(
            "avml non installé",
            "avml (Azure Volatile Memory Library) n'est pas détecté. \
             Pour un dump mémoire forensique : installer avml depuis GitHub (microsoft/avml).",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "which avml → introuvable",
            "https://github.com/microsoft/avml — binaire statique, pas d'installation système requise",
        ));
    }

    findings
}

/// Lance un dump mémoire via avml (uniquement en mode actif).
pub fn run_avml_dump() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if run_command("which", &["avml"]).map_or(true, |o| o.trim().is_empty()) {
        findings.push(HardwareFinding::new(
            "avml absent — dump mémoire ignoré",
            "avml n'est pas dans le PATH. \
             Installer : wget https://github.com/microsoft/avml/releases/latest/download/avml",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "avml introuvable",
            "sudo install avml /usr/local/bin/avml",
        ));
        return findings;
    }

    // avml nécessite les droits root
    let output = run_command("avml", &[AVML_OUTPUT]);

    match output {
        None => {
            findings.push(HardwareFinding::new(
                "Dump mémoire avml échoué",
                "avml n'a pas pu démarrer. Vérifier que l'outil est exécutable \
                 et que les droits root sont disponibles.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("avml {} → échec lancement", AVML_OUTPUT),
                "Exécuter nevelio-hw avec sudo en mode --active.",
            ));
        }
        Some(_) if Path::new(AVML_OUTPUT).exists() => {
            let size = std::fs::metadata(AVML_OUTPUT)
                .map(|m| m.len())
                .unwrap_or(0);
            findings.push(HardwareFinding::new(
                format!("Dump mémoire physique réussi ({:.1} MB)", size as f64 / 1_048_576.0),
                format!(
                    "avml a capturé la RAM physique dans {}. \
                     Analyser avec Volatility3 pour extraire processus, connexions réseau, \
                     clés de chiffrement et artefacts forensiques.",
                    AVML_OUTPUT
                ),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("Fichier : {} ({} bytes)", AVML_OUTPUT, size),
                "Analyser avec : vol3 -f {} windows.pslist  ou  vol3 -f {} linux.pslist",
            ));
        }
        Some(out) => {
            findings.push(HardwareFinding::new(
                "Dump mémoire avml — résultat inattendu",
                "avml a produit une sortie mais le fichier de dump est absent.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                out.chars().take(300).collect::<String>(),
                "Vérifier l'espace disque disponible et les droits d'écriture sur /tmp.",
            ));
        }
    }

    findings
}

/// Charge le module LiME si le .ko est disponible.
#[cfg(target_os = "linux")]
pub fn run_lime_dump(output_path: &str) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if !Path::new(LIME_MODULE).exists() {
        findings.push(HardwareFinding::new(
            "Module LiME absent — dump noyau ignoré",
            "Le module LiME (Linux Memory Extractor) n'est pas présent. \
             Compiler depuis hardware/c/kernel/lime_wrapper.c ou cloner lime-forensics.",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("{} introuvable", LIME_MODULE),
            "cd hardware/c/kernel && make && sudo insmod lime.ko",
        ));
        return findings;
    }

    let format_path = format!("path={},format=lime", output_path);
    let out = run_command("insmod", &[LIME_MODULE, &format_path]);

    if out.is_some() {
        findings.push(HardwareFinding::new(
            "Module LiME chargé — dump mémoire en cours",
            format!(
                "LiME a été inséré avec format=lime, sortie : {}. \
                 Le fichier sera disponible après l'écriture complète.",
                output_path
            ),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            format!("insmod {} path={},format=lime", LIME_MODULE, output_path),
            "Analyser avec Volatility3 après déchargement : sudo rmmod lime",
        ));
    }

    findings
}

#[cfg(not(target_os = "linux"))]
pub fn run_lime_dump(_output_path: &str) -> Vec<HardwareFinding> {
    vec![HardwareFinding::new(
        "LiME disponible uniquement sur Linux",
        "Le module LiME est un module noyau Linux. Indisponible sur macOS/Windows.",
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        format!("OS : {}", std::env::consts::OS),
        "Utiliser avml (multi-plateforme) ou LiME sur un système Linux.",
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avml_detection_does_not_panic() {
        let findings = detect_avml();
        assert!(!findings.is_empty());
    }

    #[test]
    fn lime_dump_non_linux_informative() {
        #[cfg(not(target_os = "linux"))]
        {
            let findings = run_lime_dump("/tmp/test.lime");
            assert!(!findings.is_empty());
        }
        // Sur Linux, le test évite insmod (root requis)
        #[cfg(target_os = "linux")]
        {
            // Le fichier /tmp/lime.ko n'existe pas → finding informatif
            let findings = run_lime_dump("/tmp/test.lime");
            assert!(!findings.is_empty());
        }
    }
}
