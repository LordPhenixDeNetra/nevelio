use hw_core::{HardwareFinding, HwSeverity, run_command, read_sysfs};
use rust_i18n::t;

// ── Secure Boot ───────────────────────────────────────────────────────────────

pub(super) fn check_secure_boot() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Méthode 1 : mokutil (disponible sur Ubuntu/Fedora/Arch)
    if let Some(output) = run_command("mokutil", &["--sb-state"]) {
        let lower = output.to_lowercase();
        if lower.contains("secure boot disabled") {
            findings.push(HardwareFinding::new(
                t!("firmware.secure_boot.disabled.title").to_string(),
                t!("firmware.secure_boot.disabled.desc").to_string(),
                HwSeverity::High,
                "hw-firmware",
                Some(494),
                Some(7.5),
                format!("mokutil --sb-state : \"{}\"", output.trim()),
                t!("firmware.secure_boot.disabled.rem").to_string(),
            ));
        } else if lower.contains("secure boot enabled") {
            // Secure Boot actif — vérifier si en mode Setup (clés par défaut)
            if let Some(db_out) = run_command("mokutil", &["--db"]) {
                if db_out.contains("Microsoft") && !db_out.contains("custom") {
                    findings.push(HardwareFinding::new(
                        t!("firmware.secure_boot.ms_keys_only.title").to_string(),
                        t!("firmware.secure_boot.ms_keys_only.desc").to_string(),
                        HwSeverity::Informative,
                        "hw-firmware",
                        Some(494),
                        Some(3.0),
                        "mokutil --db indique uniquement des clés Microsoft",
                        t!("firmware.secure_boot.ms_keys_only.rem").to_string(),
                    ));
                }
            }
        } else if lower.contains("efi variables are not supported") {
            findings.push(HardwareFinding::new(
                t!("firmware.secure_boot.efi_not_accessible.title").to_string(),
                t!("firmware.secure_boot.efi_not_accessible.desc").to_string(),
                HwSeverity::Medium,
                "hw-firmware",
                Some(494),
                Some(5.0),
                format!("mokutil --sb-state : \"{}\"", output.trim()),
                t!("firmware.secure_boot.efi_not_accessible.rem").to_string(),
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
                t!("firmware.secure_boot.efi_var_disabled.title").to_string(),
                t!("firmware.secure_boot.efi_var_disabled.desc").to_string(),
                HwSeverity::High,
                "hw-firmware",
                Some(494),
                Some(7.5),
                "Variable EFI SecureBoot : valeur ≠ 1",
                t!("firmware.secure_boot.efi_var_disabled.rem").to_string(),
            ));
        }
    } else if !std::path::Path::new("/sys/firmware/efi").exists() {
        // Pas de firmware EFI du tout → démarrage Legacy BIOS
        findings.push(HardwareFinding::new(
            t!("firmware.secure_boot.legacy_bios.title").to_string(),
            t!("firmware.secure_boot.legacy_bios.desc").to_string(),
            HwSeverity::Medium,
            "hw-firmware",
            Some(494),
            Some(5.5),
            "/sys/firmware/efi n'existe pas — démarrage Legacy BIOS confirmé",
            t!("firmware.secure_boot.legacy_bios.rem").to_string(),
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
            t!("firmware.bios.dmidecode_missing.title").to_string(),
            t!("firmware.bios.dmidecode_missing.desc").to_string(),
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            "dmidecode non trouvé ou accès refusé",
            t!("firmware.bios.dmidecode_missing.rem").to_string(),
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
            let vendor_str = vendor.as_deref().unwrap_or("vendeur inconnu").to_string();
            findings.push(HardwareFinding::new(
                t!("firmware.bios.outdated.title").to_string(),
                t!("firmware.bios.outdated.desc", date = d.clone(), vendor = vendor_str.clone()).to_string(),
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
                t!("firmware.bios.outdated.rem").to_string(),
            ));
        }
    }

    // Détecter firmware de VM (QEMU, VirtualBox, VMware) — informatif
    let is_vm = output.contains("QEMU") || output.contains("VirtualBox")
             || output.contains("VMware") || output.contains("SeaBIOS");
    if is_vm {
        findings.push(HardwareFinding::new(
            t!("firmware.bios.vm_detected.title").to_string(),
            t!("firmware.bios.vm_detected.desc").to_string(),
            HwSeverity::Informative,
            "hw-firmware",
            None,
            None,
            format!("dmidecode Vendor/Version : {}", output.lines().take(10).collect::<Vec<_>>().join(" | ")),
            t!("firmware.bios.vm_detected.rem").to_string(),
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
            t!("firmware.uefi_shell.detected.title").to_string(),
            t!("firmware.uefi_shell.detected.desc").to_string(),
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
            t!("firmware.uefi_shell.detected.rem").to_string(),
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
            t!("firmware.updates.available.title").to_string(),
            t!("firmware.updates.available.desc").to_string(),
            HwSeverity::Medium,
            "hw-firmware",
            Some(1395),
            Some(5.0),
            updates.join("\n"),
            t!("firmware.updates.available.rem").to_string(),
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
