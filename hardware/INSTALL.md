# Installation — Nevelio Hardware Security (`nevelio-hw`)

Guide d'installation des dépendances système par distribution Linux, avec les
commandes exactes à copier-coller.

---

## 1. Rust toolchain (toutes plateformes)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup update stable
```

---

## 2. Dépendances système

### Ubuntu / Debian (22.04 LTS ou 24.04 LTS)

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential \
  pkg-config \
  # ── Firmware / UEFI ────────────────────────────────────
  dmidecode \
  mokutil \
  efibootmgr \
  fwupd \
  flashrom \
  # ── DMA / PCIe ─────────────────────────────────────────
  pciutils \
  usbutils \
  # ── JTAG / Debug ───────────────────────────────────────
  openocd \
  # ── Analyse binaire ────────────────────────────────────
  radare2 \
  strings \
  file \
  binwalk \
  # ── eBPF ───────────────────────────────────────────────
  clang \
  llvm \
  libbpf-dev \
  bpftool \
  linux-headers-$(uname -r) \
  # ── MSR / CPU ──────────────────────────────────────────
  msr-tools \
  # ── Sécurité / audit ───────────────────────────────────
  checksec \
  # ── Forensics mémoire ──────────────────────────────────
  volatility3 \     # ou : pip3 install volatility3
  avml              # optionnel : https://github.com/microsoft/avml
```

### Fedora / RHEL / CentOS Stream

```bash
sudo dnf install -y \
  gcc make kernel-headers kernel-devel \
  dmidecode mokutil efibootmgr fwupd flashrom \
  pciutils usbutils \
  openocd \
  radare2 binwalk \
  clang llvm libbpf-devel bpftool \
  msr-tools \
  checksec
```

> **eBPF sur Fedora :** `libbpf-devel` est dans le dépôt standard depuis Fedora 35.

### Arch Linux / Manjaro

```bash
sudo pacman -S --needed \
  base-devel linux-headers \
  dmidecode mokutil efibootmgr fwupd flashrom \
  pciutils usbutils \
  openocd \
  radare2 binwalk \
  clang llvm libbpf bpf \
  msr-tools \
  checksec

# AUR (via yay ou paru)
yay -S volatility3
```

### macOS (développement uniquement — pas d'audit matériel)

macOS ne supporte pas les vérifications kernel Linux. Le build Rust compile
sans erreur, mais la plupart des modules retourneront des findings informatifs.

```bash
# Homebrew
brew install llvm radare2

# Rust
cargo build --manifest-path hardware/Cargo.toml
# eBPF et flashrom sont désactivés automatiquement sur macOS
```

---

## 3. Python et outils d'analyse

```bash
pip3 install \
  r2pipe \          # API Python pour radare2
  binwalk \         # analyse firmware
  volatility3 \     # forensics mémoire
  angr \            # analyse symbolique (optionnel, 2–5 min d'install)
  chipwhisperer \   # power analysis (optionnel, nécessite ChipWhisperer hardware)
  numpy scipy matplotlib \  # CPA et visualisation
  scapy             # optionnel, analyse réseau
```

> **angr** est volumineux (~500MB avec ses dépendances). L'installer uniquement
> si l'analyse symbolique de firmware est nécessaire.

---

## 4. Modules kernel (LiME et MSR Reader)

Nécessitent les headers du noyau courant :

```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r)

# Compilation
make -C hardware/c/kernel/

# Chargement (dump mémoire LiME)
sudo insmod hardware/c/kernel/lime_wrapper.ko \
  path=/tmp/nevelio_memory.lime format=lime

# Audit MSR
sudo insmod hardware/c/kernel/msr_reader.ko
dmesg | grep nevelio_msr
sudo rmmod msr_reader
```

---

## 5. eBPF (Linux uniquement)

```bash
# Clang ≥ 12 requis
clang --version

# Headers BPF kernel (Ubuntu)
sudo apt-get install libbpf-dev linux-headers-$(uname -r)

# Build avec eBPF activé
cd hardware
make build-release   # ou : cargo build --release --features ebpf
```

---

## 6. JTAG / OpenOCD

```bash
# Ubuntu
sudo apt-get install openocd

# Ajouter l'utilisateur au groupe dialout (pour accès USB sans root)
sudo usermod -aG dialout $USER
sudo usermod -aG plugdev $USER
newgrp dialout

# Règles udev pour les sondes JTAG courantes
sudo cp /usr/share/openocd/contrib/60-openocd.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
```

---

## 7. Lancement rapide (une commande)

```bash
# Depuis hardware/
make install-deps   # installe toutes les dépendances (Debian/Ubuntu)
make                # compile en release
make run            # audit passif (dry-run, sans root)
make run-active     # audit complet (root + eBPF, lab uniquement)
make help           # afficher toutes les cibles
```

---

## 8. Vérification de l'installation

```bash
# Vérifier le build
cargo build --manifest-path hardware/Cargo.toml

# Vérifier les tests (40 tests attendus)
cargo test --manifest-path hardware/Cargo.toml

# Vérifier le binaire
./hardware/target/debug/nevelio-hw --help
./hardware/target/debug/nevelio-hw modules list
```

---

## Matériel optionnel

| Matériel | Usage | Priorité |
|---|---|---|
| PC de test dédié (≥8GB RAM, x86_64) | Tests Rowhammer, eBPF | 🔴 requis |
| Sonde FTDI FT232H ou J-Link | Audit JTAG embarqué | 🟠 selon scope |
| STM32 Nucleo-F446RE | Cible de test JTAG | 🟠 selon scope |
| ChipWhisperer-Nano/Lite | Power analysis | 🟡 avancé |
| FPGA Nexys A7-35T | DMA PCIe attacks | 🟢 recherche |
