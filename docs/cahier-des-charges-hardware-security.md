# Cahier des charges — Module Sécurité Hardware (Nevelio Hardware Extension)

> **Statut :** ✅ Partiellement implémenté — **v0.6.0** (52/92 tâches — 43 tests — 0 erreur)
> **Binaire :** `nevelio-hw` — outil autonome dans `hardware/`
> **Dernière mise à jour :** 2026-07-02

---

## 1. Présentation et objectifs

### 1.1 Contexte

Nevelio v0.6 est un scanner de sécurité API opérant exclusivement en **couche 7 (applicative)**
via HTTP/HTTPS. Il ne touche pas au hardware, au noyau, ni aux couches protocole inférieures.

Ce cahier des charges décrit l'extension **Nevelio Hardware Security** : un outil capable
d'auditer les vulnérabilités liées au hardware, au firmware, au noyau et aux canaux auxiliaires.
Il peut s'intégrer à Nevelio comme crate workspace optionnel, ou fonctionner en outil standalone.

### 1.2 Objectifs fonctionnels

| Priorité | Objectif |
|---|---|
| P1 | Détecter les mitigations CPU manquantes (Spectre, Meltdown, MDS, TAA) |
| P1 | Audit firmware UEFI/BIOS (Secure Boot, version, intégrité) |
| P1 | Mesure de timing oracles statistiques sur HTTP (side-channel applicatif) |
| P2 | Détection de surface d'attaque DMA (ports Thunderbolt, PCIe) |
| P2 | Détection de ports JTAG/debug ouverts sur systèmes embarqués |
| P2 | Analyse statique de firmware binaire (binwalk, extraction, strings) |
| P3 | Mesure de side-channel cache (Flush+Reload, Prime+Probe) |
| P3 | Test de résilience DRAM (pattern Rowhammer) |
| P3 | Analyse mémoire forensique (intégration Volatility 3) |
| P4 | Analyse power/EM via ChipWhisperer (besoins hardware spécifiques) |

### 1.3 Ce que l'outil ne fera PAS

- Exploitation offensive réelle en production (uniquement environnements de lab contrôlés)
- Attaques physiques nécessitant accès physique non autorisé
- Contournement de protections légales (DRM, TPM scellé)

---

## 2. Langages requis

Contrairement à Nevelio qui n'utilise que Rust, l'extension hardware nécessite **six langages**,
chacun irremplaçable pour une couche spécifique.

### 2.1 C — Couche noyau et accès hardware direct

**Pourquoi C et pas Rust ?**
L'API noyau Linux est définie en C. Les modules noyau (`*.ko`) doivent suivre les conventions
ABI du noyau (structures `struct file_operations`, macros `MODULE_LICENSE`, etc.).
Rust est supporté depuis Linux 6.1 mais reste expérimental et non portable sur tous les noyaux.

**Usages :**
```c
// Module noyau — lecture directe des MSR (Model-Specific Registers)
#include <linux/module.h>
#include <asm/msr.h>

static int __init msr_audit_init(void) {
    u64 spec_ctrl;
    rdmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
    // Bit 0 = IBRS, Bit 1 = STIBP, Bit 2 = SSBD
    pr_info("SPEC_CTRL = 0x%llx\n", spec_ctrl);
    return 0;
}
```

**Librairies C utilisées :**
- `libpci` — interrogation des périphériques PCI (détection DMA)
- `libusb-1.0` — communication avec sondes JTAG USB
- `openssl` — vérification de signatures firmware
- `libelf` — analyse ELF pour RE de binaires kernel

**Outils de build :** `gcc`, `make`, kernel headers (`linux-headers-$(uname -r)`)

---

### 2.2 Assembly (x86_64 et ARM64) — Timing précis et manipulation cache

**Pourquoi Assembly est irremplaçable ici :**
Les instructions `RDTSC`/`RDTSCP` mesurent le temps en cycles CPU (~0.3ns sur 3GHz).
`CLFLUSH` invalide une ligne de cache L1/L2/L3. Ces deux instructions sont **la fondation**
de toutes les attaques Spectre/Meltdown et des mesures Flush+Reload.
Aucun langage de haut niveau ne peut garantir que ces instructions soient émises
exactement quand et comment nécessaire — le compilateur peut les réordonner ou les optimiser.

**Exemples :**

```asm
; x86_64 — Lecture cycle counter avec barrière mémoire
flush_reload_measure:
    mfence                    ; barrière mémoire (empêche réordonnancement CPU)
    rdtsc                     ; EDX:EAX = timestamp counter
    shl rdx, 32
    or  rax, rdx              ; RAX = timestamp 64 bits
    mov rcx, rax              ; sauvegarder t0

    mov rax, [rdi]            ; accès mémoire à mesurer (cible)

    rdtscp                    ; timestamp après accès (+ barrière implicite)
    shl rdx, 32
    or  rax, rdx
    sub rax, rcx              ; RAX = delta cycles
    ret

; Flush une adresse du cache
cache_flush:
    clflush [rdi]             ; invalider la ligne de cache contenant [rdi]
    mfence
    ret
```

```asm
; ARM64 — Timing via registre CNTVCT_EL0
arm_timer_read:
    mrs x0, cntvct_el0        ; lire le compteur virtuel
    ret

arm_cache_flush:
    dc civac, x0              ; Clean + Invalidate by VA to PoC
    dsb sy                    ; barrière de synchronisation
    ret
```

**Intégration avec Rust :** via `global_asm!()` ou `core::arch::x86_64::*` pour les intrinsics.

---

### 2.3 Rust — Orchestration, sécurité, interface Nevelio

Rust est le langage principal pour :
- L'interface CLI et l'intégration dans le workspace Nevelio
- L'appel des fonctions Assembly via FFI
- L'analyse statistique des mesures (médiane, percentile)
- L'exécution des sous-processus (`std::process::Command`)
- La génération des rapports findings (réutilisation des types Nevelio)

```rust
// Appel de la fonction assembly via extern
extern "C" {
    fn flush_reload_measure(addr: *const u8) -> u64;
    fn cache_flush(addr: *const u8);
}

fn measure_access_time(addr: *const u8) -> u64 {
    unsafe { flush_reload_measure(addr) }
}

// Analyse statistique
fn detect_cache_hit(samples: &[u64]) -> bool {
    let mut s = samples.to_vec();
    s.sort_unstable();
    let median = s[s.len() / 2];
    median < CACHE_HIT_THRESHOLD_CYCLES  // typiquement 100 cycles
}
```

**Crates Rust nécessaires :**
- `cc` — compiler du code C depuis build.rs
- `nix` — syscalls POSIX (mmap, mlock, perf_event_open)
- `sysctl` — lire les paramètres noyau
- `pci` — énumération PCI en user-space
- `serialport` — communication série avec sondes JTAG
- `statistical` — médiane, écart-type, percentiles

---

### 2.4 Python — Analyse, forensics, signal processing

Python est utilisé pour les parties **analyse de données** où la précision temporelle n'est
pas critique : traitement de dumps mémoire, analyse de signaux EM/power, scripting de
frameworks spécialisés qui exposent une API Python.

**Composants Python :**

```python
# 1. Volatility 3 — analyse mémoire forensique
# Installation : pip install volatility3
from volatility3.framework import contexts, automagic, plugins
from volatility3.plugins.windows import pslist, hashdump, netscan

def analyze_memory_dump(dump_path: str) -> dict:
    ctx = contexts.Context()
    # Lister processus, extraire hashs NTLM, connexions réseau
    ...

# 2. ChipWhisperer — acquisition et analyse power traces
# Installation : pip install chipwhisperer
import chipwhisperer as cw

def capture_power_trace(target_fw: str, n_traces: int = 1000):
    scope = cw.scope()
    scope.default_setup()
    target = cw.target(scope)
    traces = []
    for _ in range(n_traces):
        scope.arm()
        target.simpleserial_write('p', bytearray(16))
        ret = scope.capture()
        traces.append(scope.get_last_trace())
    return traces

# 3. Analyse statistique CPA (Correlation Power Analysis)
import numpy as np
from scipy import stats

def correlation_power_analysis(traces: np.ndarray, plaintexts: np.ndarray) -> np.ndarray:
    """Corrélation de Pearson entre traces et hypothèses de clé."""
    n_traces, n_samples = traces.shape
    correlations = np.zeros((256, n_samples))
    for key_guess in range(256):
        hypotheses = np.array([hamming_weight(sbox[p ^ key_guess]) for p in plaintexts])
        for s in range(n_samples):
            correlations[key_guess, s] = np.abs(
                stats.pearsonr(hypotheses, traces[:, s])[0]
            )
    return correlations

def hamming_weight(x: int) -> int:
    return bin(x).count('1')

# Table S-Box AES
sbox = [0x63, 0x7c, 0x77, ...]  # 256 entrées
```

**Librairies Python nécessaires :**
```
volatility3>=2.5.0
chipwhisperer>=5.6.0
numpy>=1.24.0
scipy>=1.10.0
matplotlib>=3.7.0    # visualisation des traces power
pwntools>=4.11.0     # exploitation et communication protocoles
angr>=9.2.0          # analyse binaire symbolique
r2pipe>=1.8.0        # interface Python pour radare2
```

---

### 2.5 Shell / Bash — Interrogation système et automation

Pour les commandes qui interrogent le hardware via les interfaces standard du système
(ACPI, DMI, sysfs, procfs). Ces commandes sont appelées depuis Rust via `Command::new()`.

**Commandes clés :**

```bash
# ── CPU et mitigations ──────────────────────────────────────────────────────
# Vérifier les mitigations Spectre/Meltdown actives
cat /sys/devices/system/cpu/vulnerabilities/*

# Lire les MSR via l'outil user-space (evite le module kernel)
rdmsr 0x48  # IA32_SPEC_CTRL
rdmsr 0x10  # IA32_TIME_STAMP_COUNTER

# Informations CPU détaillées
lscpu --extended
cpuid -r  # dump complet des CPUID leaves

# ── Firmware UEFI ───────────────────────────────────────────────────────────
dmidecode -t bios          # BIOS/UEFI version, vendor, date
dmidecode -t system        # Serial, UUID (détection de VM)
efibootmgr -v              # Entrées boot EFI
mokutil --sb-state         # Secure Boot activé/désactivé
fwupdmgr get-devices       # Versions firmware via LVFS

# ── Hardware PCI et DMA ─────────────────────────────────────────────────────
lspci -vvv                 # Tous les périphériques PCI avec détails
lspci -k | grep -A2 Thunderbolt  # Détection Thunderbolt
lstopo --of txt            # Topologie hardware (NUMA, cache)

# ── Flash SPI / Firmware ────────────────────────────────────────────────────
flashrom -p internal --flash-name   # Identifier le chip flash SPI
flashrom -p internal -r bios.bin    # Dump du firmware BIOS (root requis)

# ── Analyse firmware ────────────────────────────────────────────────────────
binwalk -e firmware.bin             # Extraction des composants
strings -n 8 firmware.bin | grep -iE "(password|key|secret|token|backdoor)"
hexdump -C firmware.bin | head -32  # Magic bytes

# ── DRAM et mémoire ─────────────────────────────────────────────────────────
dmidecode -t memory        # Type DRAM, fréquence, fabricant
memtester 1M 5             # Test mémoire basique
```

---

### 2.6 eBPF / BPF CO-RE — Tracing noyau sans module kernel

eBPF permet d'injecter des programmes vérifiés dans le noyau Linux **sans** écrire un module
kernel. C'est plus sûr et portable (BPF CO-RE = Compile Once, Run Everywhere).

**Pourquoi eBPF ici :**
- Tracer les appels syscall en temps réel (détecter des comportements anormaux indicateurs d'exploitation)
- Mesurer des latences internes noyau sans modifier le kernel
- Observer les accès mémoire suspects (surveillance Rowhammer)

```c
// Programme eBPF (compilé avec clang + libbpf)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Mesure de latence des syscalls read()
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start_times SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *start = bpf_map_lookup_elem(&start_times, &pid);
    if (start) {
        u64 latency = bpf_ktime_get_ns() - *start;
        // Latence anormalement élevée → possible contention cache liée à Rowhammer
        if (latency > 1000000) {  // > 1ms
            bpf_printk("PID %d: read latency spike = %llu ns\n", pid, latency);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
```

**Toolchain eBPF :**
- `clang` + `llvm` — compiler les programmes BPF en bytecode
- `libbpf` — loader BPF CO-RE en C
- `bpftool` — inspection et chargement manuel
- `libbpf-rs` (crate Rust) — charger les programmes BPF depuis Rust

---

### 2.7 Tcl — Scripting OpenOCD (JTAG)

OpenOCD (Open On-Chip Debugger) est l'outil standard pour interfacer avec les ports JTAG
et SWD sur systèmes embarqués. Son langage de scripting est **Tcl**.

```tcl
# Script OpenOCD — audit automatisé d'une cible ARM Cortex-M
# Connexion via sonde J-Link
source [find interface/jlink.cfg]
source [find target/stm32f4x.cfg]

init
halt

# Lire les registres de protection
proc audit_read_protection {} {
    set rdp [ocd_mdw 0x1FFFC000]  ; # Option Bytes STM32
    echo "Read Protection Level: $rdp"

    # Niveau 0 = pas de protection (critique)
    if {[expr {$rdp & 0xFF}] == 0xAA} {
        echo "CRITICAL: Flash non protégé — JTAG peut lire tout le firmware"
    }
}

# Dump de la mémoire flash
proc dump_flash {output_file} {
    dump_image $output_file 0x08000000 0x100000  ; # 1MB flash
    echo "Flash dumped to $output_file"
}

audit_read_protection
shutdown
```

**Toolchain JTAG :**
- OpenOCD — daemon de communication JTAG/SWD
- J-Link / FTDI FT232H / Raspberry Pi GPIO — sondes physiques
- `urjtag` — alternative pour JTAG boundary scan
- `pyocd` (Python) — alternative pour ARM Cortex uniquement

---

### 2.8 Verilog/SystemVerilog — Attaques DMA via FPGA (optionnel, P4)

Les attaques DMA (Direct Memory Access) comme PCILeech nécessitent un périphérique FPGA
qui se présente comme un périphérique PCIe légitime et accède directement à la RAM de la
machine cible via le bus PCIe, en bypassant le CPU.

```verilog
// Exemple simplifié — TLP (Transaction Layer Packet) PCIe pour lecture DMA
// Implémentation réelle : PCILeech (github.com/ufrisk/pcileech-fpga)
module pcie_dma_read (
    input  wire        clk,
    input  wire        rst_n,
    input  wire [63:0] target_addr,   // Adresse physique à lire
    input  wire [9:0]  length,        // Longueur en DWORDs
    output reg  [31:0] tlp_header [3:0],
    output reg         tlp_valid
);
    // TLP Memory Read Request (format 64-bit)
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            tlp_valid <= 0;
        end else begin
            // Header TLP MRd64
            tlp_header[0] <= {8'h20, 8'h00, 2'b00, 10'(length)};
            tlp_header[1] <= {16'h0001, 4'hF, 4'hF, 8'h00};
            tlp_header[2] <= target_addr[63:32];
            tlp_header[3] <= target_addr[31:0];
            tlp_valid     <= 1;
        end
    end
endmodule
```

**Toolchain FPGA :**
- Xilinx Vivado (Windows/Linux) — synthèse et bitstream pour Artix-7/Kintex-7
- Yosys + nextpnr — alternative open source (FPGA iCE40/ECP5)
- PCILeech-FPGA — framework DMA attack open source (base de travail)

---

## 3. Outillage et frameworks

### 3.1 Analyse de firmware

| Outil | Langage | Rôle |
|---|---|---|
| **binwalk** | Python | Extraction automatique des composants firmware (squashfs, gzip, LZMA, etc.) |
| **Ghidra** (NSA) | Java + Python | Décompilation et analyse statique de binaires ARM/x86/MIPS |
| **radare2** | C + Python (`r2pipe`) | Analyse binaire, scripting, désassemblage |
| **angr** | Python | Analyse binaire symbolique, détection de vulnérabilités automatique |
| **FACT** | Python | Firmware Analysis and Comparison Tool — pipeline d'analyse automatisé |
| **ubi_reader** | Python | Extraction de filesystems UBI (flash NAND) |
| **jefferson** | Python | Extraction JFFS2 |
| **sasquatch** | C | Extraction squashfs avec compression non-standard (Broadcom, TP-Link) |

### 3.2 Analyse mémoire (forensics)

| Outil | Langage | Rôle |
|---|---|---|
| **Volatility 3** | Python | Analyse de dumps RAM — processus, réseaux, hashs, artefacts |
| **Rekall** | Python | Alternative à Volatility (profils noyau différents) |
| **LiME** | C (module kernel) | Acquisition de mémoire RAM sur système live |
| **avml** | Rust | Alternative à LiME, user-space, pas de module kernel requis |
| **DumpIt** | C | Acquisition mémoire Windows |

### 3.3 Side-channel et power analysis

| Outil | Langage | Rôle |
|---|---|---|
| **ChipWhisperer** | Python + C (firmware) | Acquisition de traces power/EM, CPA, template attacks |
| **Riscure Inspector** | Java | Analyse professionnelle power/EM (commercial) |
| **SCALib** | Python | Bibliothèque d'analyse side-channel (TVLA, LDA) |
| **lascar** | Python | Framework side-channel open source |

### 3.4 JTAG et debugging matériel

| Outil | Langage | Rôle |
|---|---|---|
| **OpenOCD** | C + Tcl | Interface JTAG/SWD universelle, dump flash, debug live |
| **PyOCD** | Python | Alternative Python pour ARM Cortex |
| **UrJTAG** | C | JTAG boundary scan, détection de composants |
| **JTAGenum** | C (Arduino) | Énumération automatique de ports JTAG sur PCB inconnu |
| **GDB** | C | Debugger via OpenOCD (remote target) |

### 3.5 Attaques CPU et cache

| Outil | Langage | Rôle |
|---|---|---|
| **MSR Tools** | C | Lecture/écriture des MSR CPU en user-space |
| **perf** | C | Compteurs hardware Linux (cache misses, branch mispredictions) |
| **Intel PCM** | C++ | Monitoring précis des caches Intel |
| **pyperf** | Python | Interface Python pour perf |
| **cacheutils** | C | Primitives Flush+Reload, Prime+Probe prêtes à l'emploi |
| **rowhammer-test** | C | Test de vulnérabilité Rowhammer (Google Project Zero) |
| **TRRespass** | C | Contournement des mitigations TRR des DRAM modernes |
| **spectre-meltdown-checker** | Shell | Audit rapide des mitigations noyau |

---

## 4. Hardware requis

### 4.1 Matériel minimal (laboratoire de base)

| Équipement | Prix indicatif | Rôle |
|---|---|---|
| PC de test dédié (x86_64) | 200–500 € | Machine cible pour tests hardware (ne pas tester sur la machine principale) |
| Raspberry Pi 4 | 60–80 € | Sonde JTAG via GPIO, ou cible ARM pour tests embarqués |
| FTDI FT232H breakout | 15–25 € | Sonde JTAG/SPI/I2C USB universelle |
| Câbles dupont + PCB tools | 10–20 € | Connexion aux points JTAG sur PCB |

### 4.2 Matériel intermédiaire (side-channel)

| Équipement | Prix indicatif | Rôle |
|---|---|---|
| **ChipWhisperer-Nano** | 50 € | Power analysis sur microcontrôleurs (CPA de base) |
| **ChipWhisperer-Lite** | 250 € | Power + EM analysis, glitching voltage/clock |
| **ChipWhisperer-Pro** | 1 200 € | Acquisition professionnelle, haute résolution |
| Oscilloscope numérique (≥500MHz) | 200–800 € | Acquisition manuelle de signaux EM |
| Sonde EM (antenne proche champ) | 100–300 € | Capture des émissions électromagnétiques |

### 4.3 Matériel avancé (attaques DMA)

| Équipement | Prix indicatif | Rôle |
|---|---|---|
| **FPGA Artix-7** (Nexys A7, Arty A7) | 120–250 € | Base pour PCILeech DMA attack |
| **PCILeech FPGA35** (ScreamerM2) | 300–500 € | Clé PCILeech clé-en-main (M.2 vers PCIe) |
| Câble Thunderbolt 3/4 | 30–80 € | Attaque DMA via Thunderbolt (alternative PCIe) |
| J-Link EDU | 60 € | Sonde JTAG ARM professionnelle (usage éducatif) |

### 4.4 Environnement de sécurité

- **Réseau isolé** (VLAN dédié ou câble direct) — les tests ne doivent jamais atteindre Internet
- **Machine hôte séparée** de la machine cible — ne jamais tester sur sa propre machine de travail
- **Snapshots VM** avant chaque test — Rowhammer peut corrompre des données
- **Cage de Faraday** (optionnel) — pour les tests EM afin d'éviter les interférences

---

## 5. Architecture des modules

### 5.1 Vue d'ensemble

```
nevelio/hardware/                         ← sous-répertoire du repo nevelio principal
├── crates/
│   ├── hw-core/              ✅ Phase 1 — Types partagés (HardwareFinding, HwSeverity, HwReport)
│   ├── hw-cpu/               ✅ Phase 1 — Audit mitigations CPU (Rust + Shell)
│   ├── hw-firmware/          ✅ Phase 1 — Analyse firmware UEFI (Rust + Shell)
│   ├── hw-dma/               ✅ Phase 1 — Surface DMA/Thunderbolt/PCIe (Rust + Shell)
│   ├── hw-cli/               ✅ Phase 1 — Binaire `nevelio-hw` (Rust)
│   ├── hw-sidechannel/       ✅ Phase 2 — Flush+Reload, timing oracle (Rust + ASM)
│   ├── hw-memory/            ✅ Phase 4 — Rowhammer, forensics mémoire (Rust + C + Python)
│   ├── hw-jtag/              ✅ Phase 3 — Détection JTAG, audit flash (Rust + Tcl/OpenOCD)
│   └── hw-dma-fpga/          ✅ Phase 5 — IOMMU, Thunderbolt, leechcore FFI (Rust)
├── asm/
│   ├── x86_64/
│   │   ├── timing.asm        ✅ Phase 2 — RDTSC + CLFLUSH
│   │   └── rowhammer.asm     ✅ Phase 4 — Accès DRAM répétés double-sided
│   └── aarch64/
│       ├── timing.asm        ✅ Phase 2 — CNTVCT_EL0 + DC CIVAC
│       └── cache.asm         ✅ Phase 2
├── c/
│   ├── kernel/
│   │   ├── msr_reader.c      ✅ Phase 4 — Module noyau lecture MSR (IBRS/STIBP/LSTAR)
│   │   ├── lime_wrapper.c    ✅ Phase 4 — Interface LiME pour dump mémoire
│   │   └── Makefile
│   └── userspace/
│       ├── pci_scan.c        🔲 Phase 4 — Énumération PCI via libpci (non implémenté)
│       └── rowhammer.c       ✅ Phase 4 — Test Rowhammer user-space (mmap+mlock+CLFLUSH)
├── python/
│   ├── volatility_runner.py  ✅ Phase 4 — Wrapper Volatility 3 (DKOM, malfind, hashdump)
│   ├── cpa_analysis.py       ✅ Phase 5 — CPA Pearson + TVLA Welch/SCALib + plots
│   ├── firmware_analyzer.py  ✅ Phase 3 — Pipeline binwalk + strings + r2pipe + angr
│   └── chipwhisperer_acq.py  ✅ Phase 5 — Acquisition traces CW Nano/Lite/Pro + simulation
├── tcl/
│   └── jtag_audit.tcl        ✅ Phase 3 — Script OpenOCD d'audit JTAG (STM32 RDP)
├── ebpf/
│   ├── syscall_latency.bpf.c ✅ Phase 2 — Programme eBPF suivi latence syscall
│   └── memory_access.bpf.c   ✅ Phase 2 — Détection accès mémoire anormaux
└── verilog/
    └── pcie_dma/             ✅ Phase 5 — tlp_reader.v + nexys_a7.tcl/xdc (Artix-7)
```

### 5.2 Module `hw-cpu` — Audit mitigations CPU

**Vérifications :**

| Check | Méthode | Sévérité si absent |
|---|---|---|
| Spectre v1 (CWE-1342) | `/sys/devices/system/cpu/vulnerabilities/spectre_v1` | High 7.5 |
| Spectre v2 (CWE-1342) | MSR IA32_SPEC_CTRL bit IBRS + `spectre_v2` sysfs | Critical 8.1 |
| Meltdown (CWE-1342) | `meltdown` sysfs + KPTI actif (`/proc/cpuinfo` flags) | Critical 8.1 |
| MDS / RIDL (CWE-1342) | `mds` + `tsx_async_abort` sysfs | High 6.5 |
| L1TF (CWE-1342) | `l1tf` sysfs | High 6.5 |
| Microcode à jour | `dmidecode` version microcode vs base Intel/AMD | High 7.0 |
| STIBP actif | MSR IA32_SPEC_CTRL bit 1 | Medium 5.3 |
| SSBD actif | MSR IA32_SPEC_CTRL bit 2 | Medium 5.3 |

**Implémentation (Rust) :**
```rust
pub struct CpuAuditModule;

impl CpuAuditModule {
    pub fn run(&self) -> Vec<HardwareFinding> {
        let mut findings = Vec::new();
        findings.extend(self.check_sysfs_vulnerabilities());
        findings.extend(self.check_msr_mitigations());
        findings.extend(self.check_microcode_version());
        findings
    }

    fn check_sysfs_vulnerabilities(&self) -> Vec<HardwareFinding> {
        let vuln_path = "/sys/devices/system/cpu/vulnerabilities";
        // Lire chaque fichier, détecter "Vulnerable" ou "Not affected"
        ...
    }
}
```

---

### 5.3 Module `hw-firmware` — Audit UEFI/Firmware

**Vérifications :**

| Check | Méthode | Sévérité |
|---|---|---|
| Secure Boot désactivé (CWE-494) | `mokutil --sb-state` | High 7.5 |
| BIOS/UEFI non à jour (CWE-1395) | `fwupdmgr` vs LVFS database | Medium 6.0 |
| Firmware signé (CWE-347) | Lecture Option ROM + vérification signature | High 7.0 |
| UEFI Shell exposé (CWE-276) | Détection entrée boot UEFI Shell | Medium 5.3 |
| SPI Flash protégé (CWE-1266) | `flashrom` read test (non-destructif) | Critical 8.5 |
| Strings suspects dans firmware | `binwalk + strings` sur dump | Medium 5.0 |

---

### 5.4 Module `hw-sidechannel` — Timing et cache

**Vérifications :**

| Check | Méthode | Sévérité |
|---|---|---|
| Timing oracle HTTP (CWE-208) | 500 req → médiane/percentile 95 — Δ > 2ms | Medium 5.9 |
| Flush+Reload faisable | Cache hit <100 cycles mesurable en user-space | High 7.0 |
| KASLR actif | `/proc/kallsyms` accessible par user (révèle adresses noyau) | High 6.5 |
| ASLR actif | `cat /proc/sys/kernel/randomize_va_space` ≠ 2 | Medium 5.5 |
| Stack canaries | Lecture `checksec` sur binaires système | Medium 4.5 |

---

### 5.5 Module `hw-memory` — DRAM et forensics

**Vérifications :**

| Check | Méthode | Sévérité |
|---|---|---|
| Rowhammer vulnérable (CWE-1300) | Test 100k accès rapides DRAM (ASM) | Critical 8.8 |
| TRR efficace | Pattern multi-sided Rowhammer (TRRespass) | High 7.5 |
| Dump mémoire possible sans root | `/dev/mem` accessible ou `ptrace` non restreint | High 7.0 |
| Swap chiffré (CWE-312) | `/proc/swaps` + vérification chiffrement | Medium 5.5 |
| Core dumps sans restriction (CWE-312) | `ulimit -c` + `/proc/sys/kernel/core_pattern` | Medium 4.5 |

---

### 5.6 Module `hw-dma` — Surface DMA

**Vérifications :**

| Check | Méthode | Sévérité |
|---|---|---|
| IOMMU désactivé (CWE-284) | `lspci` + `/proc/cmdline` (intel_iommu=on / amd_iommu=on) | Critical 8.5 |
| Thunderbolt Security Level (CWE-284) | `/sys/bus/thunderbolt/devices/*/security` ≠ `secure`/`dponly` | High 7.8 |
| DMA capable devices non autorisés | `lspci -v` → BusMaster non restreint | High 6.5 |
| Kernel lockdown inactif | `/sys/kernel/security/lockdown` | Medium 5.3 |

---

### 5.7 Module `hw-jtag` — Debug ports (embarqué)

**Vérifications (nécessite connexion physique ou réseau local) :**

| Check | Méthode | Sévérité |
|---|---|---|
| Port JTAG ouvert détecté | OpenOCD auto-probe (JTAGenum patterns) | Critical 9.0 |
| Read Protection Level 0 (STM32) | Lecture Option Bytes via OpenOCD | Critical 9.8 |
| Debug symbols dans firmware | `strings + objdump` sur binaire extrait | Medium 5.5 |
| UART actif (shell root exposé) | Scan série sur pins TTL | Critical 9.0 |

---

## 6. Phases de développement

### Phase 1 — Fondations (3–4 semaines)

1. Créer le workspace Cargo `nevelio-hardware` avec `hw-core` (types `HardwareFinding`, `HwSeverity`)
2. Implémenter `hw-cpu` : lecture sysfs + Shell subprocess (pas d'ASM encore)
3. Implémenter `hw-firmware` : `dmidecode`, `mokutil`, `fwupdmgr` via subprocess
4. Implémenter `hw-dma` : `lspci`, `dmesg | grep IOMMU`, sysfs Thunderbolt
5. CLI de base : `nevelio-hw scan --target local`

**Langages utilisés en Phase 1 :** Rust + Shell uniquement.
**Résultat livrable :** audit passif sur toute machine Linux sans hardware spécial.

### Phase 2 — Timing et side-channel software (3–4 semaines)

1. Écrire les fonctions ASM `timing.asm` (x86_64 et ARM64)
2. Intégrer via `cc` crate + `global_asm!()` dans `hw-sidechannel`
3. Implémenter le timing oracle HTTP (500 req, calcul statistique en Rust)
4. Charger et exécuter les programmes eBPF via `libbpf-rs`
5. Intégrer `spectre-meltdown-checker` et parser sa sortie

**Langages ajoutés en Phase 2 :** Assembly + eBPF.

### Phase 3 — Firmware et JTAG (4–6 semaines)

1. Intégrer `binwalk` via subprocess Python dans `hw-firmware`
2. Intégrer `r2pipe` (radare2) pour analyse binaire automatisée
3. Wrapper OpenOCD via Rust `Command` + parser la sortie des scripts Tcl
4. Écrire `jtag_audit.tcl` pour audit automatisé Cortex-M/A
5. Intégrer `avml` (Rust) pour acquisition mémoire live sans module kernel

**Langages ajoutés en Phase 3 :** Python + Tcl.

### Phase 4 — Rowhammer et Memory (4–6 semaines)

1. Implémenter `rowhammer.asm` : double-sided hammering avec CLFLUSH
2. Module C user-space `rowhammer.c` : `mmap` + `mlock` + patterns d'accès
3. Intégrer Volatility 3 via subprocess Python
4. Intégrer TRRespass pour bypass TRR
5. Écrire le module kernel `msr_reader.c` pour lecture MSR précise

**Langages ajoutés en Phase 4 :** C (user-space puis kernel module).

### Phase 5 — Power/EM et DMA FPGA (8–12 semaines) [optionnel]

1. Wrapper ChipWhisperer Python dans `hw-sidechannel`
2. Implémenter CPA (`cpa_analysis.py`)
3. Module `hw-dma` : test actif PCILeech (nécessite FPGA + accès PCIe)
4. Code Verilog TLP pour FPGA Artix-7
5. Documentation sécurité et avertissements légaux

**Langages ajoutés en Phase 5 :** Verilog/SystemVerilog.

---

## 7. Contraintes légales et éthiques

### 7.1 Cadre légal

Ces techniques relèvent de lois strictes dans la plupart des pays :

| Pays | Loi | Risque |
|---|---|---|
| France | Articles 323-1 à 323-8 du Code Pénal | 3 ans / 100 000 € (accès non autorisé) |
| UE | Directive NIS2 + RGPD | Amendes RGPD si données personnelles exposées |
| USA | CFAA (Computer Fraud and Abuse Act) | Peine fédérale |

**Règle absolue :** utiliser uniquement sur du matériel dont vous êtes propriétaire,
ou avec une autorisation écrite explicite (contrat de pentest signé).

### 7.2 Mesures de sécurité dans l'outil

- `--accept-legal` requis (hérité de Nevelio) + disclaimer hardware spécifique
- `--dry-run` obligatoire par défaut pour les modules P3/P4 (Rowhammer, JTAG, DMA)
- Confirmation interactive avant tout test destructif potentiel
- Log de toutes les actions dans un fichier d'audit signé (SHA-256)

---

## 8. Dépendances résumées

### 8.1 Crates Rust

```toml
[dependencies]
cc          = "1.0"        # Compilation C depuis build.rs
nix         = "0.27"       # Syscalls POSIX
sysctl      = "0.5"        # Paramètres noyau
serialport  = "4.2"        # Communication JTAG USB-série
libbpf-rs   = "0.22"       # Chargement programmes eBPF
statistical = "1.0"        # Médiane, percentile
reqwest     = "0.11"       # Requêtes HTTP (timing oracle)
```

### 8.2 Paquets système (Linux)

```bash
# Analyse CPU et firmware
sudo apt install dmidecode mokutil fwupd msr-tools linux-headers-$(uname -r)

# Analyse firmware binaire
sudo apt install binwalk radare2

# JTAG
sudo apt install openocd

# eBPF
sudo apt install clang llvm libbpf-dev bpftool

# Python
pip install volatility3 chipwhisperer numpy scipy r2pipe angr

# Flashrom (compilation depuis source recommandée)
sudo apt install flashrom
```

### 8.3 Outils optionnels

```bash
# Rowhammer
git clone https://github.com/google/rowhammer-test
git clone https://github.com/vusec/trrespass

# PCILeech (DMA)
git clone https://github.com/ufrisk/pcileech
git clone https://github.com/ufrisk/pcileech-fpga

# Spectre checker
curl -L https://meltdown.ovh -o spectre-meltdown-checker.sh
```

---

## 9. Tableau de synthèse — Langage par module

| Module | Rust | C | ASM | Python | Shell | eBPF | Tcl | Verilog |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `hw-cpu` | ✅ | — | ✅ (P2) | — | ✅ | ✅ (P2) | — | — |
| `hw-firmware` | ✅ | — | — | ✅ | ✅ | — | — | — |
| `hw-sidechannel` | ✅ | — | ✅ | ✅ (P5) | — | ✅ | — | — |
| `hw-memory` | ✅ | ✅ | ✅ | ✅ | — | ✅ | — | — |
| `hw-dma` | ✅ | ✅ | — | — | ✅ | — | — | ✅ (P5) |
| `hw-jtag` | ✅ | — | — | — | — | — | ✅ | — |
| `hw-cli` | ✅ | — | — | — | — | — | — | — |

---

## 10. Internationalisation (i18n)

### Architecture

- **Moteur :** `rust-i18n v3` — macro procédurale compilant les locales au build
- **Locales :** `hardware/crates/hw-cli/locales/{fr,en,es}.yml` — YAML hiérarchique
- **Fallback :** `fr` (français)
- **Sélection langue :** flag `--lang <code>` → `NEVELIO_LANG` → `LANG` → `fr`

### Pattern d'intégration par crate

Chaque crate bibliothèque déclare dans son `lib.rs` :

```rust
rust_i18n::i18n!("../hw-cli/locales", fallback = "fr");
```

Le chemin est relatif au répertoire du `Cargo.toml` de la crate. Cette macro
génère `_rust_i18n_t()` dans le scope de la crate. Les sous-modules utilisent
`use rust_i18n::t;` puis `t!("clé")` ou `t!("clé", param = valeur)`.

### Hiérarchie des clés YAML

```
cpu.*          hw-cpu (Spectre, microcode, ASLR, KASLR...)
firmware.*     hw-firmware (Secure Boot, flash, BIOS...)
dma.*          hw-dma (IOMMU, Thunderbolt, PCIe, lockdown...)
sidechannel.*  hw-sidechannel (timing, Flush+Reload, eBPF...)
jtag.probe.*   hw-jtag / probe.rs (détection USB sondes, UART)
jtag.openocd.* hw-jtag / openocd.rs (lancement OpenOCD, erreurs)
jtag.firmware.* hw-jtag / openocd.rs (analyse firmware Python)
fpga.*         hw-dma-fpga (IOMMU, Thunderbolt, leechcore)
memory.*       hw-memory (avml, LiME, forensics, rowhammer, swap, KASLR, ECC...)
vol.*          Python volatility_runner.py (findings Volatility 3)
```

### Couverture

| Crate / Fichier | Strings traduits | Statut |
|---|---|---|
| hw-cpu (sysfs, microcode, memory_protection) | ~20 | ✅ |
| hw-firmware (uefi, flash) | ~15 | ✅ |
| hw-dma (iommu, thunderbolt, pcie) | ~18 | ✅ |
| hw-sidechannel (timing, cache, checksec, ebpf) | ~22 | ✅ |
| hw-jtag (probe, openocd) | ~25 | ✅ |
| hw-memory (lib, avml, forensics, swap, rowhammer) | ~55 | ✅ |
| hw-dma-fpga (pcileech, leechcore) | ~12 | ✅ |
| Python volatility_runner.py | ~18 | ✅ |
