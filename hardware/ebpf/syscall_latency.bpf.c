// ============================================================================
// Nevelio Hardware Security — eBPF : mesure de latence des syscalls
//
// Programme BPF de type tracepoint qui mesure le temps d'entrée/sortie
// de chaque syscall pour le PID ciblé, et signale les latences anormalement
// élevées pouvant indiquer un side-channel temporel.
//
// Compilation :
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
//     -I/usr/include/x86_64-linux-gnu \
//     -c syscall_latency.bpf.c -o syscall_latency.bpf.o
//
// Chargement depuis Rust :
//   Via crate libbpf-rs ou via le module hw-sidechannel/src/ebpf.rs
// ============================================================================

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ── Structures de données ────────────────────────────────────────────────────

struct syscall_event {
    __u32 pid;
    __u32 tid;
    __u64 syscall_nr;
    __u64 latency_ns;    // durée d'exécution du syscall en nanosecondes
    char  comm[16];      // nom du processus
};

// ── Maps BPF ─────────────────────────────────────────────────────────────────

// Stocke le timestamp d'entrée pour chaque TID en cours de syscall
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);   // TID
    __type(value, __u64);   // timestamp d'entrée (ns)
} start_time SEC(".maps");

// Ring buffer pour remonter les événements vers l'espace utilisateur
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");

// ── Filtres configurables (modifiables depuis l'espace utilisateur) ──────────

// 0 = surveiller tous les PIDs, sinon surveiller ce PID uniquement
const volatile __u32 target_pid = 0;

// Seuil : ne remonter que les syscalls durant plus de cette valeur (ns)
// 0 = remonter tous les syscalls
const volatile __u64 latency_threshold_ns = 1000000;  // 1ms par défaut

// ── Tracepoints ──────────────────────────────────────────────────────────────

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    // Filtrer par PID si configuré
    if (target_pid != 0 && pid != target_pid)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_time, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    __u64 *start = bpf_map_lookup_elem(&start_time, &tid);
    if (!start)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&start_time, &tid);

    // Filtrer par seuil de latence
    if (latency_threshold_ns > 0 && delta < latency_threshold_ns)
        return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid        = pid;
    e->tid        = tid;
    e->syscall_nr = ctx->id;
    e->latency_ns = delta;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// Utilisation depuis l'espace utilisateur (Rust) :
//
// 1. Charger le programme eBPF compilé (.bpf.o) via libbpf-rs
// 2. Attacher les tracepoints sys_enter et sys_exit
// 3. Polling du ring buffer :
//
//    while let Some(event) = rb.next() {
//        let e = unsafe { &*(event.as_ptr() as *const SyscallEvent) };
//        if e.latency_ns > THRESHOLD {
//            report_finding("Syscall anormalement lent", ...);
//        }
//    }
//
// Cas d'usage sécurité :
//   - Détecter des traitement conditionnels dans le noyau (timing oracle kernel)
//   - Identifier des syscalls lents indiquant du swap / I/O non attendu
//   - Mesurer la latence de clock_gettime() pour détecter des manipulations TSC
//   - Profiler les accès mémoire anormaux via les page faults (SIGSEGV / #PF)
// ============================================================================
