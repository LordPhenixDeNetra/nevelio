# Nevelio Hardware Security — Documentation de l'extension

> **Version :** v0.5.0 — **72/85 tâches** — 50 tests — 9 crates — 0 warning
> **Binaire :** `nevelio-hw` (workspace `hardware/`)
> **Dernière mise à jour :** 2026-06-30

---

## Présentation

`nevelio-hw` est l'extension de sécurité matérielle de Nevelio. Elle audite les
vulnérabilités aux couches hardware, firmware, noyau et canaux auxiliaires,
en complément du scanner API `nevelio` (couche 7).

L'outil fonctionne en **outil autonome** (`nevelio-hw scan`) ou peut exporter ses
résultats au **format nevelio** (`--output nevelio-json`) pour les inclure dans un
rapport de sécurité global.

---

## Démarrage rapide

```bash
# Depuis hardware/
make install-deps        # Dépendances système (Debian/Ubuntu)
make                     # Build release

# Audit passif (sans root, sans matériel)
./target/release/nevelio-hw scan --accept-legal

# Rapport HTML
./target/release/nevelio-hw scan --accept-legal --output html --out-file audit.html

# Rapport JSON compatible nevelio principal
./target/release/nevelio-hw scan --accept-legal --output nevelio-json

# Mode actif (root, eBPF, dump RAM) — lab uniquement
sudo ./target/release/nevelio-hw scan --accept-legal --active
```

---

## Modules implémentés (9 crates)

### `hw-cpu` — Mitigations CPU
Vérifie les protections contre les attaques d'exécution spéculative.

| Check | Méthode | CWE |
|---|---|---|
| Spectre v1/v2, Meltdown, MDS, L1TF | `/sys/devices/system/cpu/vulnerabilities/*` | 1342 |
| Retbleed, TAA, SRBDS, MMIO | sysfs kernel | 1342 |
| Microcode CPU à jour | `dmidecode -t processor` | 1352 |
| NX bit (DEP) | `/proc/cpuinfo` flags | 1419 |
| SMEP/SMAP | `/proc/cpuinfo` flags | 1419 |

### `hw-firmware` — Firmware UEFI/BIOS
Vérifie l'intégrité et la configuration du firmware.

| Check | Méthode | CWE |
|---|---|---|
| Secure Boot | `mokutil --sb-state` | 1326 |
| Mises à jour firmware | `fwupdmgr get-updates` | 1395 |
| Version BIOS | `dmidecode -t bios` | 1395 |
| Flashrom (écriture BIOS) | `flashrom -p internal` (actif) | 1326 |

### `hw-dma` — Surface d'attaque DMA
Détecte les vecteurs d'attaque DMA physique.

| Check | Méthode | CWE |
|---|---|---|
| IOMMU / Intel VT-d | `dmesg` + `/sys/class/iommu` | 1274 |
| Mode Thunderbolt | `/sys/bus/thunderbolt/*/security` | 284 |
| Devices PCIe suspects | `lspci` | 1274 |
| Kernel DMA protection | `/sys/bus/platform/drivers/efi-framebuffer` | 1274 |

### `hw-sidechannel` — Canaux auxiliaires
Timing attacks et side-channels via ASM haute précision.

| Check | Méthode | CWE |
|---|---|---|
| Timing oracle HTTP | Mesures RDTSC/CNTVCT, t-test de Welch | 208 |
| Flush+Reload cache L3 | ASM x86_64 : CLFLUSH + RDTSC | 1342 |
| AES-NI disponible | `/proc/cpuinfo` flags | 327 |
| Timing endpoint cible | `--target https://...` | 208 |

### `hw-jtag` — Audit JTAG / Firmware embarqué
Détection de sondes JTAG et analyse de firmware.

| Check | Méthode | CWE |
|---|---|---|
| Sondes JTAG connectées | `lsusb` — 8 VID/PID (FTDI, J-Link, ST-Link…) | 1191 |
| Ports UART | `/dev/ttyUSB*`, `/dev/ttyACM*` | 1191 |
| OpenOCD STM32 RDP Level 0 | `tcl/jtag_audit.tcl` | 1191 |
| Analyse firmware | `firmware_analyzer.py` (binwalk + strings + r2pipe + angr) | 321 |

### `hw-memory` — Mémoire physique & Forensics
Rowhammer, ECC, dump RAM, analyse Volatility.

| Check | Méthode | CWE |
|---|---|---|
| Chiffrement swap | `/proc/swaps` + dm-crypt | 311 |
| KASLR | `/proc/sys/kernel/randomize_va_space` | 330 |
| ECC disponible | `/sys/devices/system/edac/mc` | 1278 |
| TRR (DDR4/DDR5) | `dmidecode -t memory` | 1278 |
| Rowhammer test | `c/userspace/rowhammer.c` via FFI (actif) | 1278 |
| Core dumps | `/proc/sys/kernel/core_pattern` + ulimit | 312 |
| Volatility forensics | `volatility_runner.py` (DKOM, malfind, hashdump, check_syscall) | 693 |
| Dump RAM | avml ou LiME (actif, root) | — |

### `hw-dma-fpga` — PCIe DMA FPGA
Interface leechcore et audit IOMMU/Thunderbolt approfondi.

| Check | Méthode | CWE |
|---|---|---|
| IOMMU mode strict | `/proc/cmdline` : `iommu=force` | 1274 |
| Thunderbolt security level | `/sys/bus/thunderbolt/*/security` | 284 |
| leechcore FPGA (actif) | `feature=leechcore` — nécessite PCILeech FPGA | 1274 |

---

## Outils Python

### `firmware_analyzer.py` — Analyse firmware
Pipeline complet sur une image firmware.

```bash
python3 hardware/python/firmware_analyzer.py \
    --firmware firmware.bin \
    --output findings.json
```

Étapes : binwalk extraction → strings (7 patterns secrets) → magic bytes (14 signatures)
→ r2pipe ELF (NX/PIE/Canary/RELRO) → **angr** (fonctions dangereuses : strcpy, gets, system…)

### `volatility_runner.py` — Forensics mémoire
Analyse d'un dump RAM (LiME, raw, mem).

```bash
python3 hardware/python/volatility_runner.py \
    --dump /tmp/memory.lime \
    --os linux
```

Modules Volatility lancés : `linux.pslist`, `linux.psscan` (DKOM), `linux.malfind`,
`linux.check_syscall` (hooks rootkit), `linux.netstat` (ports C2).

### `chipwhisperer_acq.py` — Acquisition power traces
```bash
# Avec hardware ChipWhisperer
python3 hardware/python/chipwhisperer_acq.py --n 500 --output traces.npz

# Mode simulation (sans hardware)
python3 hardware/python/chipwhisperer_acq.py --n 500 --simulate --output traces.npz
```

### `cpa_analysis.py` — Correlation Power Analysis
```bash
# CPA AES-128 + TVLA + graphiques
python3 hardware/python/cpa_analysis.py \
    --traces traces.npz \
    --tvla \
    --plot \
    --output-key recovered_key.hex

# Démo sans hardware (traces simulées)
python3 hardware/python/cpa_analysis.py --simulate --n 500 --tvla --plot
```

---

## Journal d'audit

Chaque scan produit un journal signé SHA-256 dans `~/.local/share/nevelio-hw/audit.log`.
Chaque entrée contient un hash SHA-256 de l'entrée précédente (chaînage), ce qui permet
de détecter toute modification ultérieure du journal.

Format : `TIMESTAMP|ACTION|FINDINGS|MAX_SEVERITY|ELAPSED_MS|HASH`

---

## Format de rapport

| Format | Commande | Usage |
|---|---|---|
| Texte | `--output text` (défaut) | Terminal, lisibilité |
| JSON natif | `--output json` | Intégration CI, scripts |
| JSON nevelio | `--output nevelio-json` | Import dans rapport nevelio principal |
| HTML | `--output html --out-file audit.html` | Livrable client |

---

## Bilan — Ce que nevelio-hw couvre

| Capacité | nevelio v0.6 | nevelio-hw v0.5.0 |
|---|---|---|
| Timing HTTP (SQLi, CMDi time-based) | ✅ | ✅ (haute précision RDTSC) |
| Side-channel timing oracle | ❌ | ✅ hw-sidechannel |
| Mitigations CPU (Spectre, Meltdown…) | ❌ | ✅ hw-cpu |
| Firmware UEFI / Secure Boot | ❌ | ✅ hw-firmware |
| Analyse firmware embarqué | ❌ | ✅ binwalk + r2pipe + angr |
| IOMMU / DMA protection | ❌ | ✅ hw-dma + hw-dma-fpga |
| JTAG / Debug ports | ❌ | ✅ hw-jtag + OpenOCD |
| Rowhammer DRAM | ❌ | ✅ hw-memory (ASM + C + FFI) |
| Forensics RAM (Volatility) | ❌ | ✅ hw-memory + volatility_runner.py |
| Power Analysis (CPA/TVLA) | ❌ | ✅ cpa_analysis.py + SCALib |
| PCIe DMA FPGA (PCILeech) | ❌ | ✅ hw-dma-fpga + verilog/pcie_dma/ |
| Rapport unifié | ✅ | ✅ `--output nevelio-json` |

---

## Ce qui reste (matériel physique requis)

| Tâche | Matériel nécessaire |
|---|---|
| Test Rowhammer réel | Machine dédiée (jamais en prod) |
| Volatility sur dump VM réel | VM Linux publiée (projet Volatility) |
| JTAG sur STM32 Nucleo | STM32 Nucleo-F446RE + sonde J-Link/ST-Link |
| Acquisition traces CPA | ChipWhisperer Nano/Lite |
| PCIe DMA FPGA | Nexys A7-35T + Vivado |
| Thunderbolt DMA test | Câble TB3 + machine cible |

---

## Installation

Voir [INSTALL.md](../hardware/INSTALL.md) pour les commandes détaillées par distribution
(Ubuntu, Fedora, Arch) et les dépendances Python, eBPF, JTAG, modules kernel.

## Légal

Voir [LEGAL.md](../hardware/LEGAL.md) — Code Pénal 323-1/323-8, NIS2, CRA, RGPD,
CFAA, template de lettre d'autorisation.
