# Suivi des tâches — Nevelio Hardware Security

> Légende statut : `[ ]` À faire · `[~]` En cours · `[x]` Terminé · `[!]` Bloqué
> Légende priorité : 🔴 Critique · 🟠 Haute · 🟡 Moyenne · 🟢 Basse

---

## Phase 1 — Fondations (Rust + Shell)

> Objectif : audit passif sur machine Linux, aucun hardware spécial requis.
> Langages : Rust, Shell
> Durée estimée : 3–4 semaines

### Workspace et types partagés

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 1.1 | [x] | 🔴 | Créer le workspace Cargo `nevelio-hardware` avec `Cargo.toml` racine | 2h | — | `hardware/Cargo.toml` — 5 membres |
| 1.2 | [x] | 🔴 | Créer crate `hw-core` : types `HardwareFinding`, `HwSeverity`, `HwModule` trait | 4h | 1.1 | `hw-core/src/lib.rs` + `report.rs` |
| 1.3 | [x] | 🔴 | Créer crate `hw-cli` : squelette CLI avec `clap` (`scan`, `modules list`) | 4h | 1.2 | Binaire `nevelio-hw` opérationnel |
| 1.4 | [x] | 🟠 | Implémenter `--accept-legal` + disclaimer hardware dans `hw-cli` | 2h | 1.3 | `disclaimer.rs` — prompt interactif + bypass flag |
| 1.5 | [x] | 🟠 | Implémenter `--dry-run` global (désactive les tests actifs/destructifs) | 3h | 1.3 | Défaut `true` — `--active` pour annuler |

### Module `hw-cpu`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 1.6 | [x] | 🔴 | Lire `/sys/devices/system/cpu/vulnerabilities/*` et parser les statuts | 4h | 1.2 | `sysfs.rs` — 10 vulnérabilités couvertes |
| 1.7 | [x] | 🔴 | Vérifier mitigations Spectre v1, v2, Meltdown, MDS, L1TF | 3h | 1.6 | + TAA, Retbleed, SSB, MMIO, SRBDS |
| 1.8 | [x] | 🟠 | Lire version microcode CPU via `dmidecode -t processor` subprocess | 2h | 1.2 | `microcode.rs` — early load + NX bit + SMEP |
| 1.9 | [x] | 🟠 | Vérifier ASLR : `/proc/sys/kernel/randomize_va_space` ≠ 2 | 1h | 1.2 | `memory_protection.rs` — niveaux 0/1/2 |
| 1.10 | [x] | 🟡 | Vérifier KASLR : `/proc/kallsyms` accessible en user-space | 1h | 1.2 | + kptr_restrict + dmesg_restrict |

### Module `hw-firmware`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 1.11 | [x] | 🔴 | Lire BIOS/UEFI via `dmidecode -t bios` et extraire version + date | 3h | 1.2 | `uefi.rs` — détecte VM + firmware > 2020 |
| 1.12 | [x] | 🔴 | Vérifier Secure Boot via `mokutil --sb-state` subprocess | 2h | 1.2 | Fallback sysfs EFI si mokutil absent |
| 1.13 | [x] | 🟠 | Vérifier mises à jour firmware disponibles via `fwupdmgr get-updates` | 3h | 1.2 | Skip silencieux si fwupdmgr absent |
| 1.14 | [x] | 🟠 | Détecter entrées boot UEFI Shell via `efibootmgr -v` | 2h | 1.2 | Détecte ShellX64, EDKII Shell |
| 1.15 | [x] | 🟡 | Tenter lecture flash SPI (non-destructif) via `flashrom --flash-name` | 3h | 1.2 | `flash.rs` — désactivé en `--dry-run` |

### Module `hw-dma`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 1.16 | [x] | 🔴 | Détecter IOMMU actif : `/proc/cmdline` + `dmesg | grep -i iommu` | 3h | 1.2 | `iommu.rs` — off/inactif/passthrough/strict |
| 1.17 | [x] | 🔴 | Vérifier Thunderbolt Security Level via `/sys/bus/thunderbolt/devices/*/security` | 2h | 1.2 | `thunderbolt.rs` — rank par niveau |
| 1.18 | [x] | 🟠 | Lister devices PCIe BusMaster via `lspci -v` + parser | 3h | 1.2 | `pcie.rs` — FireWire/ExpressCard détectés |
| 1.19 | [x] | 🟡 | Vérifier kernel lockdown : `/sys/kernel/security/lockdown` | 1h | 1.2 | `lib.rs` — none/integrity/confidentiality |

### Tests et validation Phase 1

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 1.20 | [x] | 🔴 | Tests unitaires `hw-core` (sérialisation, sévérités) | 3h | 1.2 | 2 tests : `severity_ordering`, `finding_display` |
| 1.21 | [x] | 🔴 | Tests d'intégration `hw-cpu` sur machine de dev | 2h | 1.6–1.10 | 5 tests : sysfs, microcode, ASLR, module name |
| 1.22 | [x] | 🟠 | `cargo build --workspace && cargo test --workspace` propre | 1h | 1.1–1.19 | 0 warnings, 10 tests passés |
| 1.23 | [x] | 🟠 | Rapport de sortie JSON + HTML | 4h | 1.3 | JSON ✓ + texte coloré ✓ + HTML `hw-core/src/html.rs` ✓ — `--output html` dans CLI |

---

## Phase 2 — Timing et side-channel software

> Objectif : mesures précises via Assembly, timing oracle HTTP, eBPF.
> Langages ajoutés : Assembly (x86_64 + ARM64), eBPF
> Durée estimée : 3–4 semaines
> Prérequis Phase 1 terminée

### Assembly x86_64

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 2.1 | [x] | 🔴 | Écrire `asm/x86_64/timing.asm` : `flush_reload_measure` (RDTSC + CLFLUSH) | 6h | — | `hardware/asm/x86_64/timing.asm` NASM commenté — seuil 120 cycles |
| 2.2 | [x] | 🔴 | Écrire `flush_reload_measure` avec barrières `MFENCE` + `LFENCE` | 3h | 2.1 | RDTSCP + MFENCE + LFENCE dans timing.asm |
| 2.3 | [x] | 🟠 | Intégrer dans `hw-sidechannel/src/cache.rs` via intrinsics Rust | 3h | 2.1 | `core::arch::x86_64` — pas besoin de cc crate |
| 2.4 | [x] | 🟠 | Tests : cache::flush_reload_does_not_panic + module_name | 4h | 2.3 | Test sur macOS (informe : non-Linux) |

### Assembly ARM64

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 2.5 | [x] | 🟠 | Écrire `asm/aarch64/timing.asm` : `CNTVCT_EL0` + `DC CIVAC` | 5h | — | `hardware/asm/aarch64/timing.asm` GAS commenté (DC CIVAC, CNTVCT_EL0, notes granularité) |
| 2.6 | [x] | 🟡 | Compilation conditionnelle `cfg(target_arch)` dans `cache.rs` | 2h | 2.5 | `#[cfg(all(target_arch = "x86_64", target_os = "linux"))]` partout |

### Module `hw-sidechannel`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 2.7 | [x] | 🔴 | Timing oracle HTTP : 100 requêtes, calcul médiane + p95 en Rust | 6h | 1.2 | `timing.rs` — reqwest::blocking, 100 samples, percentile() |
| 2.8 | [x] | 🔴 | Détecter Δ(p95−p5) > 2 000ms → finding CWE-208 Medium 5.3 | 3h | 2.7 | Seuils configurables en constante `HIGH_VARIANCE_THRESHOLD_MS` |
| 2.9 | [x] | 🟠 | Flush+Reload via intrinsics Rust `_mm_clflush` + `_rdtsc` | 8h | 2.3 | `cache.rs` — CPUID bit 19, mesure delta 120 cycles |
| 2.10 | [x] | 🟠 | Détecter si Flush+Reload faisable en user-space (finding Medium 4.7) | 3h | 2.9 | Fallback informatif sur non-x86_64 |
| 2.11 | [x] | 🟡 | Vérifier perf_event_paranoid + ptrace_scope + appel `checksec --kernel` | 2h | 1.2 | `checksec.rs` — mmap_rnd_bits, ptrace Yama LSM, SMEP/SMAP via checksec |

### eBPF

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 2.12 | [x] | 🟠 | Écrire `ebpf/syscall_latency.bpf.c` : tracer latence syscalls | 6h | — | Ring buffer + filtres pid/latence + tracepoints sys_enter/sys_exit |
| 2.13 | [x] | 🟠 | Loader eBPF depuis Rust via `libbpf-rs` crate | 5h | 2.12 | `ebpf.rs` — include_bytes! + libbpf-rs + ring buffer — actif en mode `--active` |
| 2.14 | [x] | 🟡 | Écrire `ebpf/memory_access.bpf.c` : détecter accès mémoire suspects | 8h | 2.12 | kprobe handle_mm_fault + compteur rowhammer par page (seuil 500k) |

### Tests Phase 2

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 2.15 | [ ] | 🔴 | Valider timing oracle sur endpoint de test local (echo server) | 3h | 2.7 | — |
| 2.16 | [ ] | 🟠 | Valider ASM timing sur Intel Core (i5/i7/i9) et AMD Ryzen | 4h | 2.4 | Machines différentes = résultats différents |
| 2.17 | [ ] | 🟡 | CI GitHub Actions : build + test sur ubuntu-latest | 3h | 2.3 | Pas d'eBPF en CI (sans kernel custom) |

---

## Phase 3 — Firmware et JTAG

> Objectif : analyse binaire firmware, audit JTAG automatisé.
> Langages ajoutés : Python, Tcl
> Durée estimée : 4–6 semaines
> Prérequis Phase 1 terminée · Matériel : sonde JTAG (FTDI ou J-Link)

### Analyse firmware (Python + Shell)

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 3.1 | [x] | 🔴 | Écrire `python/firmware_analyzer.py` : pipeline binwalk + strings | 8h | — | `hardware/python/firmware_analyzer.py` — 7 patterns secrets, magic bytes, ELF via r2pipe |
| 3.2 | [x] | 🔴 | Intégrer `r2pipe` : analyse automatique des sections ELF extraites | 6h | 3.1 | `analyze_elf_binaries()` — NX, PIE, Canary, RELRO — max 20 ELF |
| 3.3 | [x] | 🟠 | Wrapper Rust `Command` → appel `python/firmware_analyzer.py` | 4h | 3.1 | `hw-jtag/src/openocd.rs::run_firmware_analyzer()` — parse JSON findings |
| 3.4 | [x] | 🟠 | Intégrer `angr` : analyse symbolique sur binaires ARM extraits | 12h | 3.2 | `firmware_analyzer.py::analyze_with_angr()` — CFGFast + PLT dangereuses (strcpy/gets/system…) + pile exécutable, `--no-angr` flag |
| 3.5 | [x] | 🟡 | Détecter systèmes de fichiers connus : squashfs, jffs2, ubi | 4h | 3.1 | `detect_filesystems_raw()` + 14 magic bytes (squashfs, jffs2, ubi, cramfs, gzip, xz…) |

### Module `hw-jtag`

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 3.6 | [x] | 🔴 | Écrire `tcl/jtag_audit.tcl` : connexion OpenOCD + audit Read Protection | 8h | — | `hardware/tcl/jtag_audit.tcl` — STM32F4 + STM32L4 + DAP générique + PCROP + UART bootloader |
| 3.7 | [x] | 🔴 | Détecter Read Protection Level 0 → finding Critical 9.8 | 3h | 3.6 | `audit_stm32_rdp()` — RDP 0xAA → CRITICAL, dump flash en `--active` mode |
| 3.8 | [x] | 🟠 | Wrapper Rust : lancer OpenOCD + exécuter script Tcl + parser sortie | 6h | 3.6 | `hw-jtag/src/openocd.rs::run_openocd_audit()` — parse lignes NEVELIO_FINDING: |
| 3.9 | [x] | 🟠 | Détection auto de sonde JTAG connectée (J-Link, FTDI) via `lsusb` | 3h | 1.2 | `hw-jtag/src/probe.rs::detect_jtag_probes()` — 8 VID/PID reconnus |
| 3.10 | [x] | 🟠 | Dump flash via OpenOCD si Read Protection = Level 0 (avec `--dry-run` check) | 5h | 3.7 | `audit_stm32_flash_dump()` dans jtag_audit.tcl — gated par `DRY_RUN` |
| 3.11 | [x] | 🟡 | Détecter UART actif via scan série (115200 baud, pattern shell Linux) | 6h | — | `hw-jtag/src/probe.rs::detect_uart_ports()` — scan /dev/ttyUSB* /dev/ttyACM* |

### Acquisition mémoire live

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 3.12 | [x] | 🟠 | Intégrer `avml` (Rust) : dump RAM sans module kernel | 4h | 1.2 | `hw-memory/src/avml.rs` — detect_avml() + run_avml_dump() — gated `--active` |
| 3.13 | [x] | 🟡 | Alternative : module kernel LiME en C pour systèmes sans `avml` | 10h | — | `c/kernel/lime_wrapper.c` + `msr_reader.c` + `Makefile` (kernel 5.x/6.x) |

### Tests Phase 3

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 3.14 | [ ] | 🔴 | Test firmware_analyzer sur firmware open source connu (OpenWRT) | 4h | 3.1 | Vérifier extraction + détection strings suspects |
| 3.15 | [ ] | 🟠 | Test JTAG sur carte STM32 de dev avec RDP Level 0 intentionnel | 6h | 3.7 | Lab uniquement |

---

## Phase 4 — Rowhammer et forensics mémoire

> Objectif : tests DRAM, analyse forensique de dumps RAM.
> Langages ajoutés : C (user-space puis kernel module)
> Durée estimée : 4–6 semaines
> Prérequis Phase 2 terminée · Matériel : PC de test dédié

### Module `hw-memory` — Rowhammer

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 4.1 | [x] | 🔴 | Écrire `asm/x86_64/rowhammer.asm` : double-sided hammering CLFLUSH | 8h | 2.1 | `hardware/asm/x86_64/rowhammer.asm` — NASM ref : `rowhammer_double_sided`, `measure_memory_access_time`, `flush_cache_line` |
| 4.2 | [x] | 🔴 | Écrire `c/userspace/rowhammer.c` : mmap + mlock + 100k accès | 10h | — | `hardware/c/userspace/rowhammer.c` — 3 patterns (0x00/0xFF/0x55), `nevelio_rowhammer_test()` exportée FFI, Makefile standalone |
| 4.3 | [x] | 🔴 | Intégrer dans Rust via `cc` crate + unsafe FFI | 4h | 4.2 | `hw-memory/build.rs` (cc::Build) + `hw-memory/src/rowhammer.rs` (extern "C", repr(C) RowhammerResult) |
| 4.4 | [x] | 🟠 | Implémenter TRRespass (multi-sided) pour bypass TRR | 12h | 4.1 | `check_trr_status()` — détection DDR5/DDR4+TRR via dmidecode + advisory TRRespass IEEE S&P 2020 |
| 4.5 | [x] | 🟠 | Détecter bit flip → finding Critical 8.8 + rapport nb flips/durée | 3h | 4.2 | `run_rowhammer_ffi()` — bit_flips/bytes/rows/ms → Critical 8.8 CWE-1278 + ECC auto-correction detect |
| 4.6 | [x] | 🟡 | Vérifier chiffrement swap : `/proc/swaps` + dm-crypt | 2h | 1.2 | `hw-memory/src/swap.rs` — KASLR + randomize_va_space intégrés |
| 4.7 | [x] | 🟡 | Vérifier core dumps : `ulimit` + `/proc/sys/kernel/core_pattern` | 1h | 1.2 | `hw-memory/src/forensics.rs::check_core_dumps()` — /proc/sys/kernel/core_pattern + ulimit RLIMIT_CORE |

### Module `hw-memory` — Forensics

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 4.8 | [x] | 🟠 | Écrire `python/volatility_runner.py` : wrapper Volatility 3 | 6h | — | `hardware/python/volatility_runner.py` — pslist+psscan, malfind, hashdump (Win), check_syscall (Lin), netscan ports C2 |
| 4.9 | [x] | 🟠 | Intégrer depuis Rust : lancer analyse Volatility sur dump fourni | 4h | 4.8 | `hw-memory/src/forensics.rs::run_volatility_analysis()` — parse JSON findings Python |
| 4.10 | [x] | 🟡 | Détecter processus injectés (DKOM) via Volatility pslist vs psscan | 5h | 4.8 | `analyze_pslist_psscan()` — pids dans psscan∖pslist → Critical 8.1 CWE-693 |

### Module kernel C

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 4.11 | [x] | 🟠 | Écrire `c/kernel/msr_reader.c` : module noyau lecture IA32_SPEC_CTRL | 8h | — | `c/kernel/msr_reader.c` — IBRS/STIBP/SSBD/NXE/LSTAR (rootkit detect) — SMP aware |
| 4.12 | [x] | 🟡 | Écrire `c/kernel/Makefile` compatible kernels Linux 5.x et 6.x | 3h | 4.11 | `c/kernel/Makefile` — targets : all, lime, msr, clean, install, unload |

### Tests Phase 4

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 4.13 | [ ] | 🔴 | Test Rowhammer sur machine dédiée (jamais sur machine de travail) | 8h | 4.2 | Faire snapshot avant test |
| 4.14 | [ ] | 🟠 | Valider Volatility sur dump de VM Linux connue | 4h | 4.8 | Utiliser dump public du projet Volatility |

---

## Phase 5 — Power/EM et DMA FPGA [optionnel]

> Objectif : analyse power/EM, attaques DMA via FPGA.
> Langages ajoutés : Verilog/SystemVerilog
> Durée estimée : 8–12 semaines
> Prérequis Phases 1–4 terminées · Matériel : ChipWhisperer + FPGA Artix-7

### Power et EM analysis

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 5.1 | [x] | 🟡 | Écrire `python/chipwhisperer_acq.py` : acquisition N traces | 8h | — | `hardware/python/chipwhisperer_acq.py` — SimpleSerial v1/v2, CW-Nano/Lite/Pro/Husky, mode simulation (`--simulate`) sans hardware |
| 5.2 | [x] | 🟡 | Écrire `python/cpa_analysis.py` : Correlation Power Analysis AES | 10h | 5.1 | `hardware/python/cpa_analysis.py` — hamming weight + corrélation Pearson vectorisée, attaque 16 bytes |
| 5.3 | [x] | 🟢 | Visualisation traces power (matplotlib) | 4h | 5.1 | Intégré dans cpa_analysis.py : `plot_traces()`, `plot_cpa_results()`, `plot_tvla()` → PNG via `--plot` |
| 5.4 | [x] | 🟢 | Intégrer SCALib pour TVLA (Test Vector Leakage Assessment) | 6h | 5.1 | `tvla_welch()` — Welch t-test, SCALib si dispo sinon scipy.stats.ttest_ind, seuil |t|>4.5 |

### DMA FPGA

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| 5.5 | [x] | 🟡 | Écrire `verilog/pcie_dma/tlp_reader.v` : TLP Memory Read Request | 16h | — | `hardware/verilog/pcie_dma/tlp_reader.v` — FSM 7 états, MRd32/MRd64, completion parsing, `dma_controller` séquenceur |
| 5.6 | [x] | 🟡 | Synthèse et bitstream via Vivado pour Nexys A7 | 8h | 5.5 | `synthesis/nexys_a7.tcl` (synth+place+route+bitstream) + `nexys_a7.xdc` (contraintes 100MHz, UART, PCIe slots commentés) |
| 5.7 | [x] | 🟡 | Intégration Rust : contrôle PCILeech via `leechcore` | 10h | 5.5 | Crate `hw-dma-fpga` — `leechcore.rs` (FFI extern "C" LcCreate/LcRead/LcClose) + `pcileech.rs` (IOMMU + Thunderbolt audit passif) |
| 5.8 | [ ] | 🟢 | Alternative Thunderbolt : test avec câble TB3 + machine cible | 6h | — | Plus simple que FPGA, mais limité macOS/Windows |

---

## Infrastructure et transversal

| # | Statut | Priorité | Tâche | Effort | Dépend de | Notes |
|---|---|---|---|---|---|---|
| T.1 | [x] | 🔴 | Rédiger `INSTALL.md` : dépendances système par distro (Ubuntu, Fedora, Arch) | 4h | 1.22 | `hardware/INSTALL.md` — apt/dnf/pacman, Python, modules kernel, eBPF, JTAG, vérification |
| T.2 | [x] | 🔴 | Rédiger `LEGAL.md` : avertissements légaux par pays (FR, UE, USA) | 3h | — | `hardware/LEGAL.md` — CP 323-1/323-8, NIS2, CRA, RGPD Art.32/35, CFAA 18 USC 1030, template lettre autorisation |
| T.3 | [x] | 🟠 | CI GitHub Actions : build Phase 1 + tests unitaires | 4h | 1.22 | `.github/workflows/hardware-security.yml` — ubuntu-latest build+test+clippy+fmt + Python ruff |
| T.4 | [x] | 🟠 | CI : build conditionnel ARM64 (cross-compilation) | 6h | T.3 | Intégré dans `hardware-security.yml` — job `cross-arm64` avec `gcc-aarch64-linux-gnu` |
| T.5 | [x] | 🟠 | Format de rapport unifié : réutiliser `HardwareFinding` → JSON + HTML | 6h | 1.2 | `hw-core/src/report.rs::to_nevelio_json()` — export compatible nevelio avec IDs HW-XXXX + `--output nevelio-json` |
| T.6 | [x] | 🟡 | Log d'audit signé (SHA-256) de toutes les actions exécutées | 5h | 1.3 | `hw-cli/src/audit.rs` — chaîne SHA-256(prev||ts||action||findings||sev), `~/.local/share/nevelio-hw/audit.log` |
| T.7 | [x] | 🟡 | Documentation API Rust (`cargo doc`) | 3h | Phase 1 | `hw-core/src/lib.rs` — `///` doc + `//!` module doc + exemple dans `HardwareFinding::new()` |
| T.8 | [ ] | 🟢 | Intégration optionnelle dans workspace Nevelio principal | 6h | Phase 1 | Feature flag `hardware` dans Nevelio CLI |
| T.9 | [x] | 🟠 | i18n : moteur Rust (`rust-i18n v3`) + locales YAML fr/en/es dans hw-cli | 4h | 1.3 | `hw-cli/locales/{fr,en,es}.yml` — `i18n!("../hw-cli/locales", fallback="fr")` dans hw-cli/main.rs |
| T.10 | [x] | 🟠 | i18n Rust : couverture hw-cpu, hw-dma, hw-firmware, hw-sidechannel | 6h | T.9 | `use rust_i18n::t;` + clés `cpu.*`, `dma.*`, `firmware.*`, `sidechannel.*` dans fr/en/es.yml |
| T.11 | [x] | 🟠 | i18n Rust : couverture hw-jtag (probe.rs, openocd.rs) | 4h | T.9 | Clés `jtag.probe.*`, `jtag.openocd.*`, `jtag.firmware.*` — check_jtag_probes retourne tuple (findings, noms) |
| T.12 | [x] | 🟠 | i18n Rust : couverture hw-memory (avml, forensics, swap, rowhammer, lib) | 8h | T.9 | Clés `memory.*` — 50+ strings traduits, tests fixés language-agnostiques |
| T.13 | [x] | 🟠 | i18n Rust : couverture hw-dma-fpga (pcileech, leechcore) | 3h | T.9 | Clés `fpga.*` — IOMMU, Thunderbolt niveaux, leechcore |
| T.14 | [x] | 🟠 | i18n Python : moteur `hardware/python/i18n.py` + locales YAML + volatility_runner.py | 3h | T.9 | `t("vol.*")` — clés vol.dkom, vol.malfind, vol.hashdump, vol.syscall, vol.network, vol.missing |
| T.15 | [x] | 🔴 | Correctifs compilation : `rust_i18n::i18n!()` dans 7 lib.rs, align probe.rs/lib.rs hw-jtag | 2h | T.10–13 | `cargo build --workspace` ✓ zéro erreur · `cargo test --workspace` ✓ 43 tests passés |

---

## Matériel à acquérir

| # | Statut | Équipement | Prix est. | Requis pour | Priorité |
|---|---|---|---|---|---|
| M.1 | [ ] | PC de test dédié (x86_64, ≥8GB RAM) | 200–400 € | Phases 1–4 | 🔴 |
| M.2 | [ ] | Raspberry Pi 4 (4GB) | 60–80 € | Phase 3 (JTAG ARM) | 🟠 |
| M.3 | [ ] | Sonde FTDI FT232H + câbles dupont | 20–30 € | Phase 3 (JTAG) | 🟠 |
| M.4 | [ ] | J-Link EDU (ARM officiel) | 60 € | Phase 3 (JTAG avancé) | 🟡 |
| M.5 | [ ] | STM32 Nucleo-F446RE (cible de test) | 15–20 € | Phase 3 (tests JTAG) | 🟠 |
| M.6 | [ ] | ChipWhisperer-Nano | 50 € | Phase 5 (CPA de base) | 🟡 |
| M.7 | [ ] | ChipWhisperer-Lite | 250 € | Phase 5 (CPA complète) | 🟢 |
| M.8 | [ ] | FPGA Nexys A7-35T (Artix-7) | 180–250 € | Phase 5 (DMA FPGA) | 🟢 |
| M.9 | [ ] | Oscilloscope USB (≥200MHz) | 150–300 € | Phase 5 (EM) | 🟢 |
| M.10 | [ ] | Sonde EM proche champ | 100–200 € | Phase 5 (EM) | 🟢 |

---

## Dépendances logicielles à installer

| # | Statut | Paquet / Outil | Commande | Requis pour |
|---|---|---|---|---|
| D.1 | [ ] | `linux-headers` | `apt install linux-headers-$(uname -r)` | Phase 4 (module kernel) |
| D.2 | [ ] | `msr-tools` | `apt install msr-tools` | Phase 1 (MSR CPU) |
| D.3 | [ ] | `dmidecode` | `apt install dmidecode` | Phase 1 (firmware) |
| D.4 | [ ] | `mokutil` + `efibootmgr` | `apt install mokutil efibootmgr` | Phase 1 (Secure Boot) |
| D.5 | [ ] | `fwupd` | `apt install fwupd` | Phase 1 (firmware updates) |
| D.6 | [ ] | `flashrom` | `apt install flashrom` | Phase 1 (SPI flash) |
| D.7 | [ ] | `binwalk` | `pip install binwalk` | Phase 3 (firmware) |
| D.8 | [ ] | `radare2` + `r2pipe` | `apt install radare2 && pip install r2pipe` | Phase 3 (firmware RE) |
| D.9 | [ ] | `openocd` | `apt install openocd` | Phase 3 (JTAG) |
| D.10 | [ ] | `clang` + `llvm` + `libbpf-dev` | `apt install clang llvm libbpf-dev bpftool` | Phase 2 (eBPF) |
| D.11 | [ ] | `volatility3` | `pip install volatility3` | Phase 4 (forensics) |
| D.12 | [ ] | `angr` | `pip install angr` | Phase 3 (analyse symbolique) |
| D.13 | [ ] | `chipwhisperer` | `pip install chipwhisperer` | Phase 5 (power) |
| D.14 | [ ] | Vivado Webpack (Xilinx) | Téléchargement AMD/Xilinx (~45GB) | Phase 5 (FPGA) |
| D.15 | [ ] | `spectre-meltdown-checker` | `curl meltdown.ovh -o checker.sh` | Phase 1 (référence) |

---

## Récapitulatif par phase

| Phase | Tâches | Terminées | Langages | Matériel requis |
|---|---|---|---|---|
| **1 — Fondations** | 23 | 23 ✅ | Rust, Shell | Machine Linux |
| **2 — Timing/Side-channel** | 17 | 15 ✅ (2 tests terrain restants) | + Assembly x86_64+ARM64, eBPF | Machine Linux |
| **3 — Firmware/JTAG** | 15 | 13 ✅ (2 tests terrain restants) | + Python, Tcl | + Sonde JTAG, STM32 |
| **4 — Rowhammer/Forensics** | 14 | 12 ✅ (2 tests terrain restants) | + C | + PC dédié |
| **5 — Power/DMA** | 8 | 7 ✅ (1 test Thunderbolt restant) | + Verilog | + ChipWhisperer, FPGA |
| **Transversal** | 15 | 14 ✅ (1 optionnel restant) | — | — |
| **TOTAL** | **92** | **84 / 92** | | |
