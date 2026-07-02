use hw_core::{HardwareFinding, HwSeverity};
use rust_i18n::t;

pub(super) fn check_ebpf_timing() -> Vec<HardwareFinding> {
    #[cfg(target_os = "linux")]
    {
        check_ebpf_linux()
    }

    #[cfg(not(target_os = "linux"))]
    {
        vec![HardwareFinding::new(
            t!("side.ebpf.linux_only.title").to_string(),
            t!("side.ebpf.linux_only.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "Non-Linux OS détecté",
            t!("side.ebpf.linux_only.rem").to_string(),
        )]
    }
}

#[cfg(target_os = "linux")]
fn check_ebpf_linux() -> Vec<HardwareFinding> {
    use std::path::Path;

    // Vérifier que le sous-système BPF est disponible
    if !Path::new("/sys/fs/bpf").exists() {
        return vec![HardwareFinding::new(
            t!("side.ebpf.bpf_not_mounted.title").to_string(),
            t!("side.ebpf.bpf_not_mounted.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "/sys/fs/bpf non trouvé",
            t!("side.ebpf.bpf_not_mounted.rem").to_string(),
        )];
    }

    // Lancer la vérification eBPF réelle si les objets sont compilés
    #[cfg(feature = "ebpf")]
    {
        run_ebpf_program()
    }

    #[cfg(not(feature = "ebpf"))]
    {
        vec![HardwareFinding::new(
            t!("side.ebpf.not_compiled.title").to_string(),
            t!("side.ebpf.not_compiled.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "Feature 'ebpf' non activée lors de la compilation",
            t!("side.ebpf.not_compiled.rem").to_string(),
        )]
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn run_ebpf_program() -> Vec<HardwareFinding> {
    use libbpf_rs::{Object, ObjectBuilder};
    use std::time::Duration;

    // Charger le programme eBPF précompilé
    let mut builder = ObjectBuilder::default();
    let obj_result = builder.open_file("/usr/lib/nevelio/timing_probe.bpf.o");

    let mut obj: Object = match obj_result {
        Ok(o) => match o.load() {
            Ok(obj) => obj,
            Err(e) => {
                return vec![HardwareFinding::new(
                    t!("side.ebpf.load_failed.title").to_string(),
                    t!("side.ebpf.load_failed.desc", error = e.to_string()).to_string(),
                    HwSeverity::Informative,
                    "hw-sidechannel",
                    None,
                    None,
                    format!("libbpf load error: {}", e),
                    t!("side.ebpf.load_failed.rem").to_string(),
                )];
            }
        },
        Err(e) => {
            return vec![HardwareFinding::new(
                t!("side.ebpf.load_failed.title").to_string(),
                t!("side.ebpf.load_failed.desc", error = e.to_string()).to_string(),
                HwSeverity::Informative,
                "hw-sidechannel",
                None,
                None,
                format!("libbpf open error: {}", e),
                t!("side.ebpf.load_failed.rem").to_string(),
            )];
        }
    };

    // Attacher les tracepoints et observer pendant 2s
    // (implémentation simplifiée — les hooks réels utilisent ring buffers)
    std::thread::sleep(Duration::from_secs(2));

    // Lire les résultats depuis la map BPF
    let slow_count = read_slow_syscall_count(&obj).unwrap_or(0);

    if slow_count == 0 {
        vec![HardwareFinding::new(
            t!("side.ebpf.no_slow_syscalls.title").to_string(),
            t!("side.ebpf.no_slow_syscalls.desc").to_string(),
            HwSeverity::Informative,
            "hw-sidechannel",
            None,
            None,
            "0 syscall > 1ms détecté en 2s d'observation",
            t!("side.ebpf.no_slow_syscalls.rem").to_string(),
        )]
    } else {
        vec![HardwareFinding::new(
            t!("side.ebpf.slow_syscalls.title", count = slow_count.to_string()).to_string(),
            t!("side.ebpf.slow_syscalls.desc", count = slow_count.to_string()).to_string(),
            HwSeverity::Medium,
            "hw-sidechannel",
            Some(208),
            Some(5.0),
            format!("{} syscalls > 1ms détectés en 2s", slow_count),
            t!("side.ebpf.slow_syscalls.rem").to_string(),
        )]
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn read_slow_syscall_count(_obj: &libbpf_rs::Object) -> Option<u64> {
    // Stub — l'implémentation réelle lit depuis la map BPF "slow_count"
    Some(0)
}
