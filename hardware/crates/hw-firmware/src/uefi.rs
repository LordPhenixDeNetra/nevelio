use hw_core::{HardwareFinding, HwSeverity, run_command, read_sysfs};

// ── Secure Boot ───────────────────────────────────────────────────────────────

pub(super) fn check_secure_boot() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Méthode 1 : mokutil (disponible sur Ubuntu/Fedora/Arch)
    if let Some(output) = run_command("mokutil", &["--sb-state"]) {
        let lower = output.to_lowercase();
        if lower.contains("secure boot disabled") {
            findings.push(HardwareFinding::new(
                "Secure Boot désactivé — CWE-494",
                "Secure Boot est désactivé. Un attaquant ayant un accès physique \
                 (ou exploitant un bootloader vulnérable) peut charger un bootkit \
                 ou un driver noyau non signé qui persiste après réinstallation OS.",
                HwSeverity::High,
                "hw-firmware",
                Some(494),
                Some(7.5),
                format!("mokutil --sb-state : \"{}\"", output.trim()),
                "Activer Secure Boot dans les paramètres UEFI. Sur Linux, enregistrer \
                 les clés MOK via `mokutil --import <clé.der>` si nécessaire.",
            ));
        } else if lower.contains("secure boot enabled") {
            // Secure Boot actif — vérifier si en mode Setup (clés par défaut)
            if let Some(db_out) = run_command("mokutil", &["--db"]) {
                if db_out.contains("Microsoft") && !db_out.contains("custom") {
                    findings.push(HardwareFinding::new(
                        "Secure Boot actif avec clés Microsoft uniquement",
                        "Secure Boot est activé mais utilise uniquement les clés \
                         Microsoft par défaut. Des bootkits signés par Microsoft \
                         (ou via des certificats compromis) pourraient contourner \
                         la protection.",
                        HwSeverity::Informative,
                        "hw-firmware",
                        Some(494),
                        Some(3.0),
                        "mokutil --db indique uniquement des clés Microsoft",
                        "Envisager d'ajouter une clé personnalisée via MOK Manager \
                         pour renforcer la chaîne de confiance.",
                    ));
                }
            }
        } else if lower.contains("efi variables are not supported") {
            findings.push(HardwareFinding::new(
                "Variables EFI non accessibles — Secure Boot non vérifiable",
                "Le système ne supporte pas les variables EFI ou le système \
                 n'a pas démarré en mode UEFI. Secure Boot ne peut pas être vérifié. \
                 Le système démarre peut-être en mode Legacy BIOS sans protection.",
                HwSeverity::Medium,
                "hw-firmware",
                Some(494),
                Some(5.0),
                format!("mokutil --sb-state : \"{}\"", output.trim()),
                "Démarrer le système en mode UEFI natif (désactiver le Legacy/CSM \
                 dans les paramètres BIOS). Vérifier que `/sys/firmware/efi` existe.",
            ));
        }
        return findings;
    }

    // Méthode 2 : sysfs UEFI si mokutil absent
    if let Some(sb_value) = read_sysfs(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    ) {
        // La variable SecureBoot est un binaire ; dernier octet = 0x01 si activé
        if sb_value.bytes().last() != Some(1) {
            findings.push(HardwareFinding::new(
                "Secure Boot désactivé (variable EFI) — CWE-494",
                "La variable UEFI SecureBoot indique que Secure Boot est désactivé.",
                HwSeverity::High,
                "hw-firmware",
                Some(494),
                Some(7.5),
                "Variable EFI SecureBoot : valeur ≠ 1",
                "Activer Secure Boot dans les paramètres UEFI.",
            ));
        }
    } else if !std::path::Path::new("/sys/firmware/efi").exists() {
        // Pas de firmware EFI du tout → démarrage Legacy BIOS
        findings.push(HardwareFinding::new(
            "Démarrage en mode Legacy BIOS (pas de UEFI)",
            "Le système a démarré en mode Legacy BIOS. Les protections UEFI \
             (Secure Boot, variables EFI sécurisées) ne sont pas disponibles. \
             Un attaquant avec accès physique peut installer un bootkit MBR.",
            HwSeverity::Medium,
            "hw-firmware",
            Some(494),
            Some(5.5),
            "/sys/firmware/efi n'existe pas — démarrage Legacy BIOS confirmé",
            "Convertir le disque de MBR vers GPT et activer le mode UEFI natif \
             dans les paramètres BIOS.",
        ));
    }

    findings
}

// ── Informations BIOS ─────────────────────────────────────────────────────────

pub(super) fn check_bios_info() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(output) = run_command("dmidecode", &["-t", "bios"]) else {
        // dmidecode absent ou pas de droits root
        findings.push(HardwareFinding::new(
            "dmidecode non disponible — audit BIOS incomplet",
            "`dmidecode` est absent ou nécessite des droits root. La version \
             du firmware BIOS/UEFI et la date de publication ne peuvent pas être vérifiées.",
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            "dmidecode non trouvé ou accès refusé",
            "Installer `dmidecode` (`apt install dmidecode`) et relancer avec sudo.",
        ));
        return findings;
    };

    let version = extract_dmi_field(&output, "Version");
    let date    = extract_dmi_field(&output, "Release Date");
    let vendor  = extract_dmi_field(&output, "Vendor");

    // Détecter firmware très ancien (avant 2020) — heuristique par année
    if let Some(ref d) = date {
        let year = d.split('/').last()
            .or_else(|| d.split('-').next())
            .and_then(|y| y.parse::<u32>().ok())
            .unwrap_or(9999);

        if year < 2020 {
            findings.push(HardwareFinding::new(
                "Firmware BIOS/UEFI potentiellement obsolète",
                format!(
                    "Le firmware BIOS/UEFI date de {} ({}). Un firmware ancien \
                     peut manquer de correctifs de sécurité critiques pour les \
                     vulnérabilités CPU (Spectre, Meltdown, MDS) et les attaques \
                     firmware (BootHole, ThinkPwn, etc.).",
                    d, vendor.as_deref().unwrap_or("vendeur inconnu")
                ),
                HwSeverity::Medium,
                "hw-firmware",
                Some(1395),
                Some(6.0),
                format!(
                    "dmidecode: Version={}, Date={}, Vendor={}",
                    version.as_deref().unwrap_or("?"),
                    d,
                    vendor.as_deref().unwrap_or("?")
                ),
                "Vérifier les mises à jour firmware sur le site du fabricant de la \
                 carte mère ou via `fwupdmgr update`. Sauvegarder le firmware actuel \
                 avant toute mise à jour.",
            ));
        }
    }

    // Détecter firmware de VM (QEMU, VirtualBox, VMware) — informatif
    let is_vm = output.contains("QEMU") || output.contains("VirtualBox")
             || output.contains("VMware") || output.contains("SeaBIOS");
    if is_vm {
        findings.push(HardwareFinding::new(
            "Système exécuté dans une machine virtuelle",
            "Le firmware détecté correspond à une machine virtuelle (QEMU/VirtualBox/VMware). \
             Certains checks hardware ne s'appliquent pas dans ce contexte. \
             Les tests Rowhammer et DMA seront sans effet.",
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            format!("dmidecode Vendor/Version : {}", output.lines().take(10).collect::<Vec<_>>().join(" | ")),
            "Aucune action requise — information contextuelle.",
        ));
    }

    findings
}

// ── UEFI Shell ────────────────────────────────────────────────────────────────

pub(super) fn check_uefi_shell() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(output) = run_command("efibootmgr", &["-v"]) else {
        return findings; // efibootmgr absent — skip silencieux
    };

    let has_uefi_shell = output.lines().any(|l| {
        let lower = l.to_lowercase();
        lower.contains("uefi shell") || lower.contains("shellx64")
            || lower.contains("shellia32") || lower.contains("edkii shell")
    });

    if has_uefi_shell {
        findings.push(HardwareFinding::new(
            "UEFI Shell détecté dans les entrées boot — CWE-276",
            "Une entrée boot pointant vers un UEFI Shell a été trouvée. \
             Un attaquant avec accès physique peut démarrer sur le UEFI Shell \
             et contourner les protections OS, lire/modifier le flash SPI, \
             ou désactiver Secure Boot.",
            HwSeverity::Medium,
            "hw-firmware",
            Some(276),
            Some(5.3),
            format!(
                "efibootmgr -v contient une entrée Shell :\n{}",
                output.lines()
                    .filter(|l| l.to_lowercase().contains("shell"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            "Supprimer l'entrée UEFI Shell : `efibootmgr -b <XXXX> -B`. \
             Activer un mot de passe UEFI pour protéger les paramètres de démarrage.",
        ));
    }

    findings
}

// ── Mises à jour firmware ─────────────────────────────────────────────────────

pub(super) fn check_firmware_updates() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    let Some(output) = run_command("fwupdmgr", &["get-updates", "--no-reboot-check"]) else {
        return findings; // fwupdmgr absent — skip silencieux
    };

    if output.contains("UPGRADES") || output.contains("Upgrade") {
        let updates: Vec<&str> = output.lines()
            .filter(|l| l.contains("Upgrade") || l.contains("→"))
            .collect();

        findings.push(HardwareFinding::new(
            "Mises à jour firmware disponibles via LVFS",
            "Des mises à jour de firmware sont disponibles via le Linux Vendor \
             Firmware Service (LVFS). Ces mises à jour peuvent contenir des correctifs \
             de sécurité critiques pour le BIOS, les SSD, ou les contrôleurs réseau.",
            HwSeverity::Medium,
            "hw-firmware",
            Some(1395),
            Some(5.0),
            updates.join("\n"),
            "Appliquer les mises à jour : `sudo fwupdmgr update`. \
             Sauvegarder les données importantes avant la mise à jour firmware.",
        ));
    }

    findings
}

// ── Utilitaires ───────────────────────────────────────────────────────────────

fn extract_dmi_field(output: &str, field: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.trim_start().starts_with(field))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
}
