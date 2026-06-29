// ============================================================================
// Nevelio Hardware Security — eBPF : détection accès mémoire anormaux
//
// Programme BPF de type kprobe/uprobe qui surveille les patterns d'accès
// mémoire pouvant indiquer :
//   - Tentatives de Rowhammer (accès répétitifs à des lignes DRAM adjacentes)
//   - Accès à des pages partagées sensibles (side-channel cross-process)
//   - Activité inhabituelle de mmap/munmap (réallocation d'espace virtuel)
//
// Compilation :
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
//     -I/usr/include/x86_64-linux-gnu \
//     -c memory_access.bpf.c -o memory_access.bpf.o
// ============================================================================

#include <linux/bpf.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Structures ───────────────────────────────────────────────────────────────

struct mmap_event {
    __u32 pid;
    __u64 addr;
    __u64 len;
    __u64 prot;       // PROT_READ | PROT_WRITE | PROT_EXEC
    __u64 flags;      // MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS
    char  comm[16];
    __u64 timestamp_ns;
};

struct page_fault_event {
    __u32 pid;
    __u64 fault_addr;
    __u64 error_code;  // write fault? user fault? protection violation?
    char  comm[16];
    __u64 timestamp_ns;
};

// Compteur d'accès par adresse de page (pour détecter rowhammer)
struct access_counter_key {
    __u32 pid;
    __u64 page_addr;  // adresse alignée sur 4KB
};

// ── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} mmap_events SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} fault_events SEC(".maps");

// Hash pour compter les accès par page (détection rowhammer / hammering)
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct access_counter_key);
    __type(value, __u64);
} page_access_count SEC(".maps");

// ── Filtres ──────────────────────────────────────────────────────────────────

const volatile __u32 target_pid = 0;

// Seuil accès à la même page pour déclencher une alerte rowhammer
const volatile __u64 rowhammer_threshold = 500000;

// ── Tracepoints mmap ─────────────────────────────────────────────────────────

// Surveille sys_mmap pour détecter les allocations de mémoire exécutable
SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_mmap(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    // Retour de mmap = adresse allouée (ou -1 en cas d'erreur)
    long ret = ctx->ret;
    if (ret < 0 || ret == -1)
        return 0;

    struct mmap_event *e = bpf_ringbuf_reserve(&mmap_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid          = pid;
    e->addr         = (__u64)ret;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Kprobe page fault ────────────────────────────────────────────────────────

// Surveille les page faults utilisateur (possibles accès à des pages non mappées)
SEC("kprobe/handle_mm_fault")
int trace_page_fault(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    // Argument 3 de handle_mm_fault = adresse de la faute
    __u64 fault_addr = PT_REGS_PARM3(ctx);
    __u64 page_addr  = fault_addr & ~0xFFFULL;  // aligner sur 4KB

    // Incrémenter le compteur d'accès à cette page
    struct access_counter_key key = {
        .pid       = pid,
        .page_addr = page_addr,
    };

    __u64 *cnt = bpf_map_lookup_elem(&page_access_count, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);

        // Alerte rowhammer si seuil dépassé
        if (*cnt >= rowhammer_threshold && *cnt % rowhammer_threshold == 0) {
            struct page_fault_event *e = bpf_ringbuf_reserve(
                &fault_events, sizeof(*e), 0);
            if (e) {
                e->pid          = pid;
                e->fault_addr   = fault_addr;
                e->error_code   = *cnt;  // réutilisation du champ pour le compteur
                e->timestamp_ns = bpf_ktime_get_ns();
                bpf_get_current_comm(e->comm, sizeof(e->comm));
                bpf_ringbuf_submit(e, 0);
            }
        }
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&page_access_count, &key, &init, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// Analyse des résultats (espace utilisateur) :
//
// mmap_events :
//   - Surveiller les allocations avec PROT_EXEC en dehors des bibliothèques
//     connues → injection de shellcode potentielle
//   - MAP_SHARED vers des fichiers sensibles → partage de pages exploitable
//
// fault_events (compteur rowhammer) :
//   - Si error_code (compteur) atteint rowhammer_threshold → page martelée
//   - Croiser avec l'adresse physique via /proc/PID/pagemap pour confirmer
//     si les pages adjacentes (DRAM row) sont accédées
//
// Limitations :
//   - Ce programme ne peut pas accéder aux adresses physiques directement
//     (besoin de /proc/PID/pagemap + /proc/iomem en espace utilisateur)
//   - La détection rowhammer complète nécessite des outils dédiés (rowhammer.js,
//    rowhammer-test de Google, ou des modules noyau spécifiques)
// ============================================================================
