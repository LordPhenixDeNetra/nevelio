// Chargeur eBPF — hw-sidechannel
//
// Conditions d'activation :
//   - target_os = linux
//   - feature "ebpf" activée (--features ebpf)
//   - has_ebpf cfg set par build.rs (clang disponible + .bpf.c compilés)
//
// Sur macOS ou sans les conditions ci-dessus : finding informatif uniquement.

use hw_core::{HardwareFinding, HwSeverity};

// ── Programmes eBPF embarqués (générés par build.rs) ─────────────────────────

#[cfg(all(target_os = "linux", feature = "ebpf", has_ebpf))]
include!(concat!(env!("OUT_DIR"), "/ebpf_programs.rs"));

// ── Struct événement (doit correspondre au struct C dans .bpf.c) ──────────────

#[cfg(target_os = "linux")]
#[repr(C)]
struct SyscallEvent {
    pid:        u32,
    tid:        u32,
    syscall_nr: u64,
    latency_ns: u64,
    comm:       [u8; 16],
}

// ── Point d'entrée public ─────────────────────────────────────────────────────

/// Vérifie les latences syscall via eBPF (observation de 2 secondes).
/// Nécessite root (CAP_BPF) — appelé en mode `--active` uniquement.
pub fn check_ebpf_timing() -> Vec<HardwareFinding> {
    let mut findings = Vec::new();

    // Vérifier la disponibilité du sous-système BPF
    if !std::path::Path::new("/sys/fs/bpf").exists() {
        findings.push(HardwareFinding::new(
            "eBPF : sous-système BPF non monté",
            "Le point de montage /sys/fs/bpf est absent. \
             Le kernel ne supporte pas BPF ou il n'est pas monté.",
            HwSeverity::Informative,
            "hw-sidechannel",
            None, None,
            "/sys/fs/bpf absent",
            "Monter bpffs : mount -t bpf none /sys/fs/bpf\n\
             Vérifier kernel ≥ 5.4 et CONFIG_BPF_SYSCALL=y.",
        ));
        return findings;
    }

    // Branche Linux + feature ebpf + has_ebpf (tout disponible)
    #[cfg(all(target_os = "linux", feature = "ebpf", has_ebpf))]
    {
        run_ebpf_loader(&mut findings);
    }

    // Branche : Linux mais feature ou compilation eBPF manquante
    #[cfg(all(target_os = "linux", not(all(feature = "ebpf", has_ebpf))))]
    {
        findings.push(HardwareFinding::new(
            "eBPF : check non compilé",
            "Les programmes eBPF n'ont pas été compilés. \
             Rebuilder avec : make build-release (sur Linux avec clang installé).",
            HwSeverity::Informative,
            "hw-sidechannel",
            None, None,
            "Feature 'ebpf' ou has_ebpf manquant",
            "sudo apt-get install clang llvm libbpf-dev\n\
             make install-deps && make build-release",
        ));
    }

    // Branche : non-Linux (macOS, Windows)
    #[cfg(not(target_os = "linux"))]
    {
        findings.push(HardwareFinding::new(
            "eBPF : disponible uniquement sur Linux",
            "Les checks eBPF (latence syscall, détection accès mémoire) \
             ne sont disponibles que sur Linux avec kernel ≥ 5.4.",
            HwSeverity::Informative,
            "hw-sidechannel",
            None, None,
            format!("OS courant : {}", std::env::consts::OS),
            "Exécuter nevelio-hw sur une machine Linux.",
        ));
    }

    findings
}

// ── Loader eBPF (Linux + feature ebpf + has_ebpf) ────────────────────────────

#[cfg(all(target_os = "linux", feature = "ebpf", has_ebpf))]
fn run_ebpf_loader(findings: &mut Vec<HardwareFinding>) {
    use std::sync::{Arc, Mutex};

    match load_and_poll(findings) {
        Ok(_) => {}
        Err(e) => {
            findings.push(HardwareFinding::new(
                "eBPF : échec du chargement du programme",
                format!(
                    "Impossible de charger le programme eBPF : {}.\n\
                     Vérifier que nevelio-hw est exécuté en root \
                     (ou avec CAP_BPF + CAP_PERFMON).",
                    e
                ),
                HwSeverity::Informative,
                "hw-sidechannel",
                None, None,
                e.to_string(),
                "sudo ./nevelio-hw scan --accept-legal --active",
            ));
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf", has_ebpf))]
fn load_and_poll(findings: &mut Vec<HardwareFinding>) -> anyhow::Result<()> {
    use libbpf_rs::{ObjectBuilder, RingBufferBuilder};
    use std::sync::{Arc, Mutex};

    // Événements capturés (comm + latency_ns)
    let events: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cb = Arc::clone(&events);

    let bytes = SYSCALL_LATENCY_BPF;

    // Charger l'objet BPF
    let open_obj = ObjectBuilder::default()
        .open_memory(bytes)
        .map_err(|e| anyhow::anyhow!("open_memory : {}", e))?;

    let mut obj = open_obj
        .load()
        .map_err(|e| anyhow::anyhow!("load : {}", e))?;

    // Attacher tracepoints
    {
        let prog = obj.prog_mut("trace_sys_enter")
            .ok_or_else(|| anyhow::anyhow!("trace_sys_enter introuvable"))?;
        prog.attach_tracepoint("raw_syscalls", "sys_enter")
            .map_err(|e| anyhow::anyhow!("attach sys_enter : {}", e))?;
    }
    {
        let prog = obj.prog_mut("trace_sys_exit")
            .ok_or_else(|| anyhow::anyhow!("trace_sys_exit introuvable"))?;
        prog.attach_tracepoint("raw_syscalls", "sys_exit")
            .map_err(|e| anyhow::anyhow!("attach sys_exit : {}", e))?;
    }

    // Ring buffer
    let map = obj.map("events")
        .ok_or_else(|| anyhow::anyhow!("map 'events' introuvable"))?;

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(map, move |data: &[u8]| -> i32 {
        if data.len() < std::mem::size_of::<SyscallEvent>() {
            return 0;
        }
        let ev = unsafe { &*(data.as_ptr() as *const SyscallEvent) };
        let comm = String::from_utf8_lossy(&ev.comm)
            .trim_end_matches('\0')
            .to_string();
        events_cb.lock().unwrap().push((comm, ev.latency_ns));
        0
    }).map_err(|e| anyhow::anyhow!("add ringbuf : {}", e))?;

    let rb = rb_builder.build()
        .map_err(|e| anyhow::anyhow!("build ringbuf : {}", e))?;

    // Observer 2 secondes
    eprintln!("  [eBPF] Observation syscall latency 2s…");
    rb.poll(Duration::from_secs(2)).ok();

    // Analyser les événements
    let captured = events.lock().unwrap();

    if captured.is_empty() {
        findings.push(HardwareFinding::new(
            "eBPF syscall latency : aucun syscall lent détecté",
            "Aucun syscall n'a dépassé le seuil de 1ms durant les 2s d'observation. \
             La distribution de latence semble normale.",
            HwSeverity::Informative,
            "hw-sidechannel",
            None, None,
            "eBPF observation 2s — 0 événement > 1ms",
            "Continuer à monitorer en production via un pipeline eBPF dédié.",
        ));
    } else {
        // Top 3 événements les plus lents
        let mut sorted: Vec<_> = captured.iter().cloned().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let top = sorted.iter().take(3)
            .map(|(comm, ns)| format!("{} ({:.1}ms)", comm, *ns as f64 / 1_000_000.0))
            .collect::<Vec<_>>()
            .join(", ");

        let severity = if captured.len() > 100 { HwSeverity::Medium } else { HwSeverity::Low };
        let cvss     = if captured.len() > 100 { 4.3 } else { 2.9 };

        findings.push(HardwareFinding::new(
            format!(
                "eBPF : {} syscall(s) > 1ms détecté(s) en 2s — CWE-208",
                captured.len()
            ),
            format!(
                "Des syscalls anormalement lents ont été observés. \
                 Une latence élevée peut indiquer un timing oracle dans le noyau, \
                 une congestion I/O exploitable, ou une activité swap non attendue. \
                 {} événements au total en 2 secondes d'observation.",
                captured.len()
            ),
            severity,
            "hw-sidechannel",
            Some(208),
            Some(cvss),
            format!("Top lents : {} | total : {} événements", top, captured.len()),
            "Analyser les processus générant des syscalls lents. \
             Vérifier kernel.perf_event_paranoid = 3 pour limiter l'accès PMU. \
             Monitorer en continu via Prometheus + eBPF exporteur.",
        ));
    }

    Ok(())
}
