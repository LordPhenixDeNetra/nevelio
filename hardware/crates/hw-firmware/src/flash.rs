use hw_core::{HardwareFinding, HwSeverity, run_command};

/// Tente de détecter le chip flash SPI et teste l'accès en lecture (non-destructif).
/// Nécessite root. Activé uniquement si `dry_run = false`.
pub(super) fn check_spi_flash() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Vérifier si flashrom est disponible
    let Some(output) = run_command("flashrom", &["-p", "internal", "--flash-name"]) else {
        findings.push(HardwareFinding::new(
            "flashrom non disponible — audit flash SPI impossible",
            "`flashrom` est absent du système. Le chip flash SPI (qui contient le \
             firmware BIOS/UEFI) ne peut pas être audité pour sa protection en écriture.",
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            "flashrom non trouvé dans PATH",
            "Installer flashrom : `apt install flashrom`. \
             Relancer avec sudo (accès hardware requis).",
        ));
        return findings;
    };

    let output_lower = output.to_lowercase();

    // Détecter les erreurs d'accès
    if output_lower.contains("permission denied") || output_lower.contains("access denied") {
        findings.push(HardwareFinding::new(
            "Accès flash SPI refusé — relancer en root",
            "flashrom nécessite des droits root pour accéder au chip flash SPI interne.",
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            "flashrom : permission denied",
            "Exécuter `nevelio-hw scan --module hw-firmware` avec sudo.",
        ));
        return findings;
    }

    // Si flashrom réussit à identifier le chip → le bus SPI est accessible
    if output_lower.contains("found") || output.lines().any(|l| l.contains("MiB")) {
        let chip_info = output.lines()
            .find(|l| l.contains("Found") || l.contains("MiB"))
            .unwrap_or("chip inconnu")
            .trim()
            .to_string();

        // Vérifier la protection en écriture (Write Protect)
        if let Some(wp_output) = run_command("flashrom", &["-p", "internal", "--wp-status"]) {
            let wp_lower = wp_output.to_lowercase();
            if wp_lower.contains("disabled") || wp_lower.contains("not enabled") {
                findings.push(HardwareFinding::new(
                    "Protection en écriture flash SPI désactivée — CWE-1266",
                    "Le chip flash SPI contenant le firmware BIOS/UEFI n'a pas de \
                     protection en écriture active. Un attaquant ayant root sur le \
                     système peut modifier le firmware directement, implantant un \
                     bootkit persistant qui survit à la réinstallation OS.",
                    HwSeverity::Critical,
                    "hw-firmware",
                    Some(1266),
                    Some(8.5),
                    format!("flashrom --wp-status : {}\nChip : {}", wp_output.trim(), chip_info),
                    "Activer la protection en écriture hardware du flash SPI dans les \
                     paramètres BIOS/UEFI. Certains fabricants l'appellent \
                     'BIOS Lock', 'Flash Write Protection' ou 'SMM BIOS Write Protection'.",
                ));
            } else if wp_lower.contains("enabled") {
                // Protection active — informer
                findings.push(HardwareFinding::new(
                    "Flash SPI : protection en écriture active",
                    "La protection en écriture du flash SPI est activée. \
                     Le firmware est protégé contre les modifications logicielles.",
                    HwSeverity::Informative,
                    "hw-firmware",
                    None,
                    None,
                    format!("flashrom --wp-status : {}", wp_output.trim()),
                    "Aucune action requise.",
                ));
            }
        } else {
            // flashrom peut lire le chip mais --wp-status non supporté sur ce chip
            findings.push(HardwareFinding::new(
                "Flash SPI accessible en lecture — protection en écriture non vérifiable",
                "Le chip flash SPI est accessible en lecture via flashrom. \
                 La commande `--wp-status` n'est pas supportée sur ce modèle de chip, \
                 il est impossible de confirmer si la protection en écriture est active.",
                HwSeverity::Low,
                "hw-firmware",
                Some(1266),
                Some(4.0),
                format!("Chip identifié : {}", chip_info),
                "Vérifier manuellement la protection en écriture dans les paramètres \
                 BIOS/UEFI. Consulter la documentation du fabricant de la carte mère.",
            ));
        }
    }

    findings
}
