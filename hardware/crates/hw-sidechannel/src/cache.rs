use hw_core::{HardwareFinding, HwSeverity};

/// Seuil en cycles CPU : en dessous = cache hit, au-dessus = cache miss.
/// Valeur typique x86_64 : ~100 cycles pour L3, ~250 pour DRAM.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
const CACHE_HIT_THRESHOLD_CYCLES: u64 = 120;

/// Mesure le temps d'accès à `addr` après vidage du cache (CLFLUSH).
///
/// Retourne `None` sur les architectures non supportées.
///
/// # Safety
/// L'adresse doit être valide et alignée sur 64 octets.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub unsafe fn flush_reload_measure(addr: *const u8) -> u64 {
    use core::arch::x86_64::{_mm_clflush, _mm_lfence, _mm_mfence, _rdtsc};

    _mm_clflush(addr);
    _mm_mfence();
    let start = _rdtsc();
    let _ = (addr as *const u64).read_volatile();
    _mm_lfence();
    let end = _rdtsc();
    end.wrapping_sub(start)
}

/// Vérifie si le processeur supporte CLFLUSH (Flush+Reload) en user-space
/// et mesure le delta cache-hit / cache-miss.
pub fn check_flush_reload() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        // Vérifie la présence de l'instruction CLFLUSH via CPUID
        // CPUID leaf 1, EDX bit 19 = CLFSH
        let has_clflush = {
            let result = unsafe { core::arch::x86_64::__cpuid(1) };
            (result.edx >> 19) & 1 == 1
        };

        if !has_clflush {
            findings.push(HardwareFinding::new(
                "CLFLUSH non supporté par ce CPU",
                "L'instruction CLFLUSH n'est pas disponible. \
                 Les attaques Flush+Reload ne sont pas applicables sur ce système.",
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                "CPUID leaf 1 EDX bit 19 = 0",
                "Aucune action requise.",
            ));
            return findings;
        }

        // Mesurer delta hit / miss sur un buffer local
        let buf = vec![0u8; 4096];
        let addr = buf.as_ptr();

        let miss_cycles = unsafe { flush_reload_measure(addr) };

        // Accès sans flush = cache hit
        let _ = unsafe { (addr as *const u64).read_volatile() };
        let hit_cycles = unsafe {
            use core::arch::x86_64::{_mm_lfence, _mm_mfence, _rdtsc};
            _mm_mfence();
            let s = _rdtsc();
            let _ = (addr as *const u64).read_volatile();
            _mm_lfence();
            let e = _rdtsc();
            e.wrapping_sub(s)
        };

        let delta = miss_cycles.saturating_sub(hit_cycles);

        if delta > CACHE_HIT_THRESHOLD_CYCLES {
            findings.push(HardwareFinding::new(
                "Flush+Reload faisable en user-space (CWE-1342)",
                "La différence de latence entre cache miss (après CLFLUSH) et \
                 cache hit est suffisamment grande pour être exploitable par \
                 une attaque Flush+Reload. Ce type d'attaque permet de déduire \
                 les patterns d'accès mémoire d'autres processus partageant \
                 des pages physiques (bibliothèques partagées, OpenSSL, etc.).",
                HwSeverity::Medium,
                "hw-sidechannel",
                Some(1342),
                Some(4.7),
                format!(
                    "cache miss = {} cycles | cache hit = {} cycles | Δ = {} cycles (seuil : {})",
                    miss_cycles, hit_cycles, delta, CACHE_HIT_THRESHOLD_CYCLES
                ),
                "Activer Kernel Page-Table Isolation (KPTI) et vérifier que \
                 `nosmt` est passé au kernel pour désactiver l'hyperthreading. \
                 Les mitigations Spectre v1/v2 réduisent la fenêtre d'attaque. \
                 Pour les applications critiques, utiliser des primitives \
                 constant-time (libsodium, boringssl avec -DOPENSSL_SMALL).",
            ));
        } else {
            findings.push(HardwareFinding::new(
                "Flush+Reload : delta cycles trop faible pour exploitation",
                "L'écart de latence cache miss / hit est insuffisant pour une \
                 attaque Flush+Reload fiable sur ce système.",
                HwSeverity::Informative,
                "hw-sidechannel",
                Some(1342), None,
                format!(
                    "cache miss = {} cycles | cache hit = {} cycles | Δ = {} cycles",
                    miss_cycles, hit_cycles, delta
                ),
                "Aucune action immédiate requise.",
            ));
        }
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        findings.push(HardwareFinding::new(
            "Flush+Reload : check non disponible sur cette plateforme",
            "Le check Flush+Reload via CLFLUSH est disponible uniquement sur \
             Linux x86_64. Sur ARM64, utiliser le timer CNTVCT_EL0.",
            HwSeverity::Informative,
            "hw-sidechannel",
            Some(1342), None,
            format!("Plateforme : {} / {}", std::env::consts::ARCH, std::env::consts::OS),
            "Exécuter ce check sur une machine Linux x86_64.",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_reload_does_not_panic() {
        let findings = check_flush_reload();
        assert!(!findings.is_empty(), "doit retourner au moins un finding informatif");
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn measure_returns_nonzero() {
        let buf = vec![0u8; 64];
        let cycles = unsafe { flush_reload_measure(buf.as_ptr()) };
        assert!(cycles > 0, "les cycles ne peuvent pas être zéro");
    }
}
