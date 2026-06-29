use hw_core::{HardwareFinding, HwSeverity};

// ── FFI vers rowhammer.c ─────────────────────────────────────────────────────

/// Structure miroir de NevelioRowhammerResult dans rowhammer.c
#[cfg(has_rowhammer)]
#[repr(C)]
struct RowhammerResult {
    bit_flips:     u64,
    bytes_flipped: u64,
    iterations:    u64,
    duration_ms:   u64,
    rows_tested:   u64,
    memory_mb:     u32,
    ecc_detected:  i32,
    vulnerable:    i32,
}

#[cfg(has_rowhammer)]
extern "C" {
    fn nevelio_rowhammer_test(
        mem_size_mb:  u32,
        hammer_count: u64,
        max_seconds:  u32,
        result:       *mut RowhammerResult,
    ) -> i32;
}

// ── Test Rowhammer complet ────────────────────────────────────────────────────

/// Lance le test Rowhammer (mode actif uniquement).
/// Taille par défaut : 128MB, 1M itérations, 60s max.
pub fn run_rowhammer_test(mem_size_mb: u32, dry_run: bool) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    if dry_run {
        findings.push(HardwareFinding::new(
            "Test Rowhammer ignoré (mode dry-run) — CWE-1278",
            "Le test Rowhammer n'est pas exécuté en mode dry-run. \
             Utiliser --active pour lancer le test sur une machine de test dédiée. \
             ATTENTION : ne jamais lancer en production.",
            HwSeverity::Informative,
            "hw-memory",
            Some(1278),
            None,
            "dry_run = true",
            "Exécuter sur une machine de lab dédiée : nevelio-hw scan --active",
        ));
        return findings;
    }

    // Ajouter une note légale systématique en mode actif
    findings.push(HardwareFinding::new(
        "Test Rowhammer lancé — résultats en cours",
        "Le test de vulnérabilité Rowhammer est actif. \
         La DRAM est testée avec un pattern double-sided hammering. \
         Ce test nécessite une autorisation écrite sur tout système tiers.",
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        format!("Zone testée : {}MB", mem_size_mb),
        "",
    ));

    #[cfg(has_rowhammer)]
    {
        findings.extend(run_rowhammer_ffi(mem_size_mb));
    }

    #[cfg(not(has_rowhammer))]
    {
        findings.push(HardwareFinding::new(
            "Rowhammer C non compilé — vérification logicielle uniquement",
            "Le binaire rowhammer.c n'a pas été compilé sur cette plateforme \
             (gcc absent, plateforme non-Linux, ou erreur de compilation). \
             Exécuter `make -C hardware/c/userspace` pour un test complet.",
            HwSeverity::Informative,
            "hw-memory",
            Some(1278), None,
            format!("OS: {}, Arch: {}", std::env::consts::OS, std::env::consts::ARCH),
            "cd hardware/c/userspace && make && sudo ./rowhammer_test",
        ));

        // Vérification logicielle : détecter si l'ECC est actif
        findings.extend(check_ecc_availability());
    }

    findings
}

#[cfg(has_rowhammer)]
fn run_rowhammer_ffi(mem_size_mb: u32) -> Vec<HardwareFinding> {
    let mut findings = Vec::new();
    let mut result = RowhammerResult {
        bit_flips:     0,
        bytes_flipped: 0,
        iterations:    0,
        duration_ms:   0,
        rows_tested:   0,
        memory_mb:     0,
        ecc_detected:  0,
        vulnerable:    0,
    };

    let rc = unsafe {
        nevelio_rowhammer_test(
            mem_size_mb.max(64),  // minimum 64MB
            1_000_000,            // 1M itérations par paire
            60,                   // 60s max
            &mut result,
        )
    };

    match rc {
        -3 => {
            findings.push(HardwareFinding::new(
                "Rowhammer non supporté sur cette plateforme",
                "Le test Rowhammer n'est disponible que sur Linux x86_64/ARM64.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("OS: {}", std::env::consts::OS),
                "",
            ));
        }
        -2 => {
            findings.push(HardwareFinding::new(
                "Rowhammer : mlock() échoué — root requis",
                "Impossible de verrouiller la mémoire en RAM physique. \
                 Le test peut produire des faux négatifs si des pages sont swappées.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "mlock() → EPERM",
                "sudo nevelio-hw scan --active",
            ));
        }
        -1 => {
            findings.push(HardwareFinding::new(
                "Rowhammer : allocation mémoire échouée",
                format!("mmap({} MB) a échoué.", mem_size_mb),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "mmap → MAP_FAILED",
                "Réduire la taille avec un paramètre personnalisé.",
            ));
        }
        0 => {
            // Rapport principal
            let duration_s = result.duration_ms / 1000;
            let hammer_rate = if result.duration_ms > 0 {
                result.iterations * result.rows_tested * 1000 / result.duration_ms
            } else {
                0
            };

            if result.vulnerable != 0 {
                findings.push(HardwareFinding::new(
                    format!(
                        "DRAM vulnérable à Rowhammer : {} bit flip(s) détecté(s) — CWE-1278",
                        result.bit_flips
                    ),
                    format!(
                        "Le test Rowhammer a détecté {} inversions de bits dans {} octets \
                         sur {} paires de rows testées en {}s ({} hammer/s). \
                         Un attaquant avec accès local peut exploiter cette vulnérabilité \
                         pour escalader ses privilèges (ex: exploitation des page tables EFI).",
                        result.bit_flips,
                        result.bytes_flipped,
                        result.rows_tested,
                        duration_s,
                        hammer_rate,
                    ),
                    HwSeverity::Critical,
                    "hw-memory",
                    Some(1278),
                    Some(8.8),
                    format!(
                        "bit_flips={}, bytes={}, rows={}, duration={}ms, ecc={}",
                        result.bit_flips, result.bytes_flipped,
                        result.rows_tested, result.duration_ms,
                        result.ecc_detected
                    ),
                    "1. Vérifier la disponibilité de l'ECC sur la carte mère (nécessite un BIOS/UEFI compatible)\n\
                     2. Appliquer les mises à jour BIOS qui activent TRR (Target Row Refresh)\n\
                     3. Remplacer les modules DRAM par des modèles DDR4 avec TRR certifié\n\
                     4. Activer le patching kernel LKDTM si disponible",
                ));

                if result.ecc_detected != 0 {
                    findings.push(HardwareFinding::new(
                        "ECC actif — bit flips corrigés automatiquement",
                        "L'ECC (Error Correcting Code) a corrigé des bit flips détectés. \
                         La vulnérabilité Rowhammer est présente mais atténuée par l'ECC. \
                         Note : l'ECC corrige 1 flip/mot, mais 2+ flips simultanés peuvent bypass.",
                        HwSeverity::Medium,
                        "hw-memory",
                        Some(1278),
                        Some(4.7),
                        "ECC corrections détectées lors du second scan",
                        "Maintenir l'ECC actif. Surveiller les logs EDAC du noyau.",
                    ));
                }
            } else {
                findings.push(HardwareFinding::new(
                    format!(
                        "Aucun bit flip Rowhammer détecté ({} paires, {}s)",
                        result.rows_tested, duration_s
                    ),
                    "Le test Rowhammer n'a pas induit de bit flips avec les paramètres testés. \
                     Un résultat négatif ne garantit pas l'absence de vulnérabilité : \
                     augmenter les itérations ou la durée pour un test plus exhaustif.",
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    format!("rows={}, iter={}, duration={}ms",
                            result.rows_tested, result.iterations, result.duration_ms),
                    "Pour un test exhaustif : ./rowhammer_test --size 512 --iters 5000000 --time 120",
                ));
            }
        }
        _ => {
            findings.push(HardwareFinding::new(
                format!("Rowhammer : erreur inattendue (rc={})", rc),
                "Le test Rowhammer a retourné un code d'erreur non reconnu.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                format!("rc = {}", rc),
                "",
            ));
        }
    }

    findings
}

// ── Vérification ECC logicielle ───────────────────────────────────────────────

/// Détecte si l'ECC est disponible et actif via les interfaces kernel Linux.
pub fn check_ecc_availability() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // L'ECC est exposé via le sous-système EDAC (Error Detection And Correction)
    let edac_path = "/sys/bus/platform/drivers/i7core_edac";
    let edac_mc   = "/sys/devices/system/edac/mc";

    let edac_available = std::path::Path::new(edac_mc).exists()
        || std::path::Path::new(edac_path).exists();

    if edac_available {
        // Lire les compteurs d'erreurs depuis EDAC
        let ce_count = read_edac_counter("/sys/devices/system/edac/mc/mc0/ce_count");
        let ue_count = read_edac_counter("/sys/devices/system/edac/mc/mc0/ue_count");

        let detail = format!(
            "/sys/devices/system/edac présent — CE={}, UE={}",
            ce_count.unwrap_or(0),
            ue_count.unwrap_or(0)
        );

        if let Some(ue) = ue_count {
            if ue > 0 {
                findings.push(HardwareFinding::new(
                    format!("EDAC : {} erreur(s) mémoire non corrigeable(s) — CWE-1278", ue),
                    "Des erreurs mémoire non corrigeables (UE = Uncorrectable Errors) \
                     ont été détectées par EDAC. Cela indique une dégradation hardware \
                     sérieuse ou une tentative d'exploitation Rowhammer réussie.",
                    HwSeverity::Critical,
                    "hw-memory",
                    Some(1278),
                    Some(8.8),
                    detail,
                    "Remplacement immédiat des modules DRAM défaillants. \
                     Analyser les logs EDAC : dmesg | grep EDAC",
                ));
            } else {
                findings.push(HardwareFinding::new(
                    "ECC / EDAC actif — 0 erreur non corrigeable",
                    "Le sous-système EDAC détecte et corrige les erreurs mémoire. \
                     Aucune erreur non corrigeable rapportée.",
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    detail,
                    "Surveiller régulièrement : cat /sys/devices/system/edac/mc/mc0/ce_count",
                ));
            }
        }
    } else {
        findings.push(HardwareFinding::new(
            "ECC/EDAC non détecté — DRAM probablement sans ECC",
            "Le sous-système EDAC est absent. La DRAM installée ne semble pas être \
             de type ECC, ou le support EDAC n'est pas compilé dans ce noyau. \
             Sans ECC, les bit flips Rowhammer sont non détectés et non corrigés.",
            HwSeverity::Medium,
            "hw-memory",
            Some(1278),
            Some(5.5),
            "/sys/devices/system/edac/mc absent",
            "Pour les serveurs et systèmes sensibles, utiliser des modules ECC RDIMM.\n\
             Vérifier que le BIOS active l'ECC et que le driver EDAC est chargé.",
        ));
    }

    findings
}

fn read_edac_counter(path: &str) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

// ── TRRespass — multi-sided hammering ────────────────────────────────────────

/// Vérifie si la DRAM annonce la présence de TRR (Target Row Refresh).
/// TRR est supposé mitiger Rowhammer mais TRRespass montre que c'est contournable.
pub fn check_trr_status() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Chercher l'info TRR dans les logs DRAM (disponible via decode-dimms ou dmidecode)
    let dmidecode_out = hw_core::run_command("dmidecode", &["-t", "memory"]);

    if let Some(out) = dmidecode_out {
        let has_ddr5 = out.to_lowercase().contains("ddr5");
        let has_ddr4 = out.to_lowercase().contains("ddr4");
        let has_ecc  = out.to_lowercase().contains("ecc") || out.to_lowercase().contains("error correction");

        if has_ddr5 {
            findings.push(HardwareFinding::new(
                "DRAM DDR5 détectée — mitigations Rowhammer améliorées",
                "DDR5 intègre un refresh rate plus élevé (32ms vs 64ms en DDR4) \
                 et des mécanismes RFM (Refresh Management) standardisés. \
                 Rowhammer reste théoriquement possible mais significativement plus difficile.",
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "dmidecode : DDR5 détecté",
                "Maintenir le firmware DRAM à jour (SPD/XMP). Activer RFM si disponible dans le BIOS.",
            ));
        } else if has_ddr4 {
            let severity = if has_ecc { HwSeverity::Low } else { HwSeverity::Medium };
            findings.push(HardwareFinding::new(
                "DRAM DDR4 détectée — TRR présent mais potentiellement contournable",
                "DDR4 avec TRR (Target Row Refresh) est présumé résistant à Rowhammer classique. \
                 Cependant, TRRespass (IEEE S&P 2020) a démontré que TRR est contournable \
                 via des patterns multi-sided (N-sided hammering). \
                 Le test nevelio-hw utilise uniquement le double-sided ; \
                 TRRespass nécessite un accès aux adresses physiques (root + huge pages).",
                severity,
                "hw-memory",
                Some(1278),
                Some(5.5),
                format!("DDR4 détecté, ECC: {}", has_ecc),
                "Mettre à jour le firmware DRAM. Activer l'ECC si la carte mère le supporte. \
                 Référence : frigo et al., 'TRRespass: Exploiting TRR Mitigations' (IEEE S&P 2020)",
            ));
        }
    } else {
        findings.push(HardwareFinding::new(
            "dmidecode absent — type DRAM inconnu",
            "Impossible de déterminer le type de DRAM et les mitigations disponibles.",
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "dmidecode introuvable",
            "sudo apt-get install dmidecode",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rowhammer_dry_run_returns_informative() {
        let findings = run_rowhammer_test(64, true);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| matches!(f.severity, HwSeverity::Informative)));
    }

    #[test]
    fn ecc_check_does_not_panic() {
        let findings = check_ecc_availability();
        assert!(!findings.is_empty());
    }

    #[test]
    fn trr_check_does_not_panic() {
        let findings = check_trr_status();
        // Peut être vide si dmidecode absent
        let _ = findings;
    }
}
