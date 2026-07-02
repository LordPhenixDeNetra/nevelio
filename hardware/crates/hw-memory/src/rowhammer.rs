use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;

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
            t!("memory.rowhammer.dry_run.title"),
            t!("memory.rowhammer.dry_run.desc"),
            HwSeverity::Informative,
            "hw-memory",
            Some(1278),
            None,
            "dry_run = true",
            t!("memory.rowhammer.dry_run.rem"),
        ));
        return findings;
    }

    // Ajouter une note légale systématique en mode actif
    findings.push(HardwareFinding::new(
        t!("memory.rowhammer.active.title"),
        t!("memory.rowhammer.active.desc"),
        HwSeverity::Informative,
        "hw-memory",
        None, None,
        t!("memory.rowhammer.active.evidence", mb = mem_size_mb),
        "",
    ));

    #[cfg(has_rowhammer)]
    {
        findings.extend(run_rowhammer_ffi(mem_size_mb));
    }

    #[cfg(not(has_rowhammer))]
    {
        findings.push(HardwareFinding::new(
            t!("memory.rowhammer.no_c.title"),
            t!("memory.rowhammer.no_c.desc"),
            HwSeverity::Informative,
            "hw-memory",
            Some(1278), None,
            t!("memory.rowhammer.no_c.evidence", os = std::env::consts::OS, arch = std::env::consts::ARCH),
            t!("memory.rowhammer.no_c.rem"),
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
                t!("memory.rowhammer.unsupported.title"),
                t!("memory.rowhammer.unsupported.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                t!("memory.rowhammer.unsupported.evidence", os = std::env::consts::OS),
                "",
            ));
        }
        -2 => {
            findings.push(HardwareFinding::new(
                t!("memory.rowhammer.mlock.title"),
                t!("memory.rowhammer.mlock.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "mlock() → EPERM",
                t!("memory.rowhammer.mlock.rem"),
            ));
        }
        -1 => {
            findings.push(HardwareFinding::new(
                t!("memory.rowhammer.alloc.title"),
                t!("memory.rowhammer.alloc.desc", mb = mem_size_mb),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "mmap → MAP_FAILED",
                t!("memory.rowhammer.alloc.rem"),
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
                    t!("memory.rowhammer.vuln.title", flips = result.bit_flips),
                    t!("memory.rowhammer.vuln.desc",
                        flips = result.bit_flips,
                        bytes = result.bytes_flipped,
                        rows  = result.rows_tested,
                        secs  = duration_s,
                        rate  = hammer_rate),
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
                    t!("memory.rowhammer.vuln.rem"),
                ));

                if result.ecc_detected != 0 {
                    findings.push(HardwareFinding::new(
                        t!("memory.rowhammer.ecc_active.title"),
                        t!("memory.rowhammer.ecc_active.desc"),
                        HwSeverity::Medium,
                        "hw-memory",
                        Some(1278),
                        Some(4.7),
                        "ECC corrections détectées lors du second scan",
                        t!("memory.rowhammer.ecc_active.rem"),
                    ));
                }
            } else {
                findings.push(HardwareFinding::new(
                    t!("memory.rowhammer.ok.title", rows = result.rows_tested, secs = duration_s),
                    t!("memory.rowhammer.ok.desc"),
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    format!("rows={}, iter={}, duration={}ms",
                            result.rows_tested, result.iterations, result.duration_ms),
                    t!("memory.rowhammer.ok.rem"),
                ));
            }
        }
        _ => {
            findings.push(HardwareFinding::new(
                t!("memory.rowhammer.error.title", rc = rc),
                t!("memory.rowhammer.error.desc"),
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
                    t!("memory.edac.ue.title", ue = ue),
                    t!("memory.edac.ue.desc"),
                    HwSeverity::Critical,
                    "hw-memory",
                    Some(1278),
                    Some(8.8),
                    detail,
                    t!("memory.edac.ue.rem"),
                ));
            } else {
                findings.push(HardwareFinding::new(
                    t!("memory.edac.ok.title"),
                    t!("memory.edac.ok.desc"),
                    HwSeverity::Informative,
                    "hw-memory",
                    None, None,
                    detail,
                    t!("memory.edac.ok.rem"),
                ));
            }
        }
    } else {
        findings.push(HardwareFinding::new(
            t!("memory.edac.missing.title"),
            t!("memory.edac.missing.desc"),
            HwSeverity::Medium,
            "hw-memory",
            Some(1278),
            Some(5.5),
            "/sys/devices/system/edac/mc absent",
            t!("memory.edac.missing.rem"),
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
                t!("memory.ddr5.title"),
                t!("memory.ddr5.desc"),
                HwSeverity::Informative,
                "hw-memory",
                None, None,
                "dmidecode : DDR5 détecté",
                t!("memory.ddr5.rem"),
            ));
        } else if has_ddr4 {
            let severity = if has_ecc { HwSeverity::Low } else { HwSeverity::Medium };
            findings.push(HardwareFinding::new(
                t!("memory.ddr4.title"),
                t!("memory.ddr4.desc"),
                severity,
                "hw-memory",
                Some(1278),
                Some(5.5),
                format!("DDR4 détecté, ECC: {}", has_ecc),
                t!("memory.ddr4.rem"),
            ));
        }
    } else {
        findings.push(HardwareFinding::new(
            t!("memory.dmidecode.missing.title"),
            t!("memory.dmidecode.missing.desc"),
            HwSeverity::Informative,
            "hw-memory",
            None, None,
            "dmidecode introuvable",
            t!("memory.dmidecode.missing.rem"),
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
