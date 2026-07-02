use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;

// Seuil de différence cache miss / hit pour que Flush+Reload soit exploitable
const DELTA_THRESHOLD_CYCLES: u64 = 200;

pub(super) fn check_flush_reload() -> Vec<HardwareFinding> {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        check_flush_reload_x86()
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    {
        vec![HardwareFinding::new(
            t!("side.cache.platform_not_supported.title").to_string(),
            t!("side.cache.platform_not_supported.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "Plateforme non-Linux ou non-x86_64",
            t!("side.cache.platform_not_supported.rem").to_string(),
        )]
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn check_flush_reload_x86() -> Vec<HardwareFinding> {
    use std::arch::x86_64::{__cpuid, _mm_clflush, _rdtsc};

    // Vérifier que CLFLUSH est supporté (CPUID.01H:EDX.bit19)
    let cpuid_result = unsafe { __cpuid(1) };
    if (cpuid_result.edx >> 19) & 1 == 0 {
        return vec![HardwareFinding::new(
            t!("side.cache.no_clflush.title").to_string(),
            t!("side.cache.no_clflush.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "CPUID.01H:EDX.bit19 = 0 (CLFLUSH non supporté)",
            t!("side.cache.no_clflush.rem").to_string(),
        )];
    }

    // Mesurer le delta entre un accès en cache et un accès après CLFLUSH
    let probe: Vec<u8> = vec![0u8; 4096];
    let ptr = probe.as_ptr();

    let delta = unsafe {
        // Accès en cache (warm)
        let _ = std::ptr::read_volatile(ptr);
        let t1 = _rdtsc();
        let _ = std::ptr::read_volatile(ptr);
        let t2 = _rdtsc();
        let warm = t2 - t1;

        // Flush + accès froid (miss)
        _mm_clflush(ptr);
        std::arch::x86_64::_mm_mfence();
        let t3 = _rdtsc();
        let _ = std::ptr::read_volatile(ptr);
        let t4 = _rdtsc();
        let cold = t4 - t3;

        cold.saturating_sub(warm)
    };

    if delta > DELTA_THRESHOLD_CYCLES {
        vec![HardwareFinding::new(
            t!("side.cache.flush_reload_feasible.title").to_string(),
            t!("side.cache.flush_reload_feasible.desc").to_string(),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(1342),
            Some(5.3),
            format!(
                "Delta cache miss/hit = {} cycles (seuil = {} cycles) — Flush+Reload faisable",
                delta, DELTA_THRESHOLD_CYCLES
            ),
            t!("side.cache.flush_reload_feasible.rem").to_string(),
        )]
    } else {
        vec![HardwareFinding::new(
            t!("side.cache.delta_too_low.title").to_string(),
            t!("side.cache.delta_too_low.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            format!("Delta cache miss/hit = {} cycles (seuil = {})", delta, DELTA_THRESHOLD_CYCLES),
            t!("side.cache.delta_too_low.rem").to_string(),
        )]
    }
}
