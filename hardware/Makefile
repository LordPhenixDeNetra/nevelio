# =============================================================================
# Nevelio Hardware Security — Makefile
# Usage : make [cible]  (depuis le répertoire hardware/)
# =============================================================================

UNAME      := $(shell uname -s)
ARCH       := $(shell uname -m)
CARGO      := cargo
MANIFEST   := Cargo.toml
BIN        := target/release/nevelio-hw
BIN_DBG    := target/debug/nevelio-hw
REPORT     ?= nevelio-hw-report.html
TARGET_URL ?=

# ── Feature flags par plateforme ─────────────────────────────────────────────
#
# Sur Linux : activer eBPF (nécessite clang + libbpf-dev installés)
# Sur macOS / autre : build sans eBPF (mode développement)
#
ifeq ($(UNAME), Linux)
    FEATURES := --features ebpf
    SUDO     := sudo
    NEED_ROOT := "root requis (CAP_BPF / CAP_SYS_ADMIN)"
else
    FEATURES :=
    SUDO     :=
    NEED_ROOT := "(macOS : eBPF non disponible)"
endif

.PHONY: all build build-release install-deps run run-active \
        run-html run-json run-target run-firmware run-jtag \
        modules test check clean kernel-modules kernel-clean help

# =============================================================================
# Cible par défaut
# =============================================================================

all: build-release

# =============================================================================
# Build
# =============================================================================

build:
	$(CARGO) build --manifest-path $(MANIFEST) $(FEATURES)

build-release:
	$(CARGO) build --release --manifest-path $(MANIFEST) $(FEATURES)

# =============================================================================
# Dépendances système
# =============================================================================

install-deps:
ifeq ($(UNAME), Linux)
	@echo "[*] Installation des dépendances sur Debian/Ubuntu..."
	@sudo apt-get update -qq
	@sudo apt-get install -y \
		dmidecode \
		mokutil efibootmgr \
		fwupd \
		flashrom \
		pciutils \
		clang llvm libbpf-dev bpftool \
		checksec \
		msr-tools \
		usbutils \
		openocd \
		binwalk \
		radare2 \
		linux-headers-$$(uname -r) \
		build-essential
	@pip3 install --quiet r2pipe binwalk 2>/dev/null || true
	@echo ""
	@echo "[✓] Dépendances système installées."
	@echo "[*] Pour Fedora/RHEL : sudo dnf install dmidecode mokutil efibootmgr fwupd flashrom pciutils clang llvm libbpf-devel bpftool checksec usbutils openocd radare2"
else ifeq ($(UNAME), Darwin)
	@echo "[!] macOS détecté."
	@echo "    Les dépendances de sécurité hardware sont Linux-spécifiques."
	@echo "    Sur macOS : uniquement le build Rust fonctionne (mode développement)."
	@echo ""
	@echo "    Pour Homebrew (outils généraux) :"
	@echo "    brew install llvm"
else
	@echo "[!] Plateforme non reconnue : $(UNAME)"
endif

# =============================================================================
# Exécution — Modes passif (dry-run)
# =============================================================================

## Audit passif complet (dry-run, sans root)
run: build-release
	@echo ""
	./$(BIN) scan --accept-legal
	@echo ""

## Rapport HTML → $(REPORT)
run-html: build-release
	@echo ""
	./$(BIN) scan --accept-legal --output html --out-file $(REPORT)
	@echo "[✓] Rapport HTML : $(REPORT)"
	@echo ""

## Rapport JSON → stdout
run-json: build-release
	./$(BIN) scan --accept-legal --output json

## Timing oracle HTTP (requiert --TARGET_URL=https://...)
run-target: build-release
	@if [ -z "$(TARGET_URL)" ]; then \
		echo ""; \
		echo "  Usage : make run-target TARGET_URL=https://api.example.com"; \
		echo ""; \
		exit 1; \
	fi
	./$(BIN) scan --accept-legal --target $(TARGET_URL)

## Timing oracle + rapport HTML
run-target-html: build-release
	@if [ -z "$(TARGET_URL)" ]; then \
		echo "Usage : make run-target-html TARGET_URL=https://... [REPORT=fichier.html]"; \
		exit 1; \
	fi
	./$(BIN) scan --accept-legal \
		--target $(TARGET_URL) \
		--output html \
		--out-file $(REPORT)
	@echo "[✓] Rapport : $(REPORT)"

# =============================================================================
# Exécution — Mode actif (root + eBPF)
# =============================================================================

## Audit actif : flashrom, eBPF, tests actifs (root requis)
run-active: build-release
	@echo ""
	@echo "[!] Mode actif — $(NEED_ROOT)"
	@echo ""
	$(SUDO) ./$(BIN) scan --accept-legal --active

## Audit actif + rapport HTML
run-active-html: build-release
	@echo "[!] Mode actif — $(NEED_ROOT)"
	$(SUDO) ./$(BIN) scan --accept-legal --active \
		--output html --out-file $(REPORT)
	@echo "[✓] Rapport : $(REPORT)"

# =============================================================================
# Modules
# =============================================================================

modules: build-release
	./$(BIN) modules list

module-show: build-release
	@if [ -z "$(MODULE)" ]; then \
		echo "Usage : make module-show MODULE=hw-cpu"; exit 1; \
	fi
	./$(BIN) modules show $(MODULE)

# =============================================================================
# Qualité
# =============================================================================

test:
	$(CARGO) test --manifest-path $(MANIFEST) $(FEATURES)

check:
	$(CARGO) clippy --manifest-path $(MANIFEST) $(FEATURES) -- -D warnings

clean:
	$(CARGO) clean --manifest-path $(MANIFEST)
	@rm -f $(REPORT)

# =============================================================================
# Analyse firmware — Python (binwalk + strings + r2pipe)
# =============================================================================

## Analyser un firmware : make run-firmware FIRMWARE=/path/to/firmware.bin
run-firmware:
	@if [ -z "$(FIRMWARE)" ]; then \
		echo ""; \
		echo "  Usage : make run-firmware FIRMWARE=/path/to/firmware.bin"; \
		echo ""; \
		exit 1; \
	fi
	python3 python/firmware_analyzer.py --firmware $(FIRMWARE)

## Analyser firmware + rapport JSON
run-firmware-json:
	@if [ -z "$(FIRMWARE)" ]; then \
		echo "Usage : make run-firmware-json FIRMWARE=/path/to/firmware.bin REPORT=out.json"; exit 1; \
	fi
	python3 python/firmware_analyzer.py --firmware $(FIRMWARE) --output $(REPORT)

# =============================================================================
# Audit JTAG — OpenOCD + Tcl
# =============================================================================

## Audit JTAG passif (dry-run) : make run-jtag IFACE=interface/ftdi/ft2232h.cfg TARGET_CFG=target/stm32f4x.cfg
run-jtag:
	@if [ -z "$(IFACE)" ] || [ -z "$(TARGET_CFG)" ]; then \
		echo ""; \
		echo "  Usage : make run-jtag IFACE=interface/ftdi/ft2232h.cfg TARGET_CFG=target/stm32f4x.cfg"; \
		echo "  Fichiers cfg OpenOCD : /usr/share/openocd/scripts/"; \
		echo ""; \
		exit 1; \
	fi
	openocd -f $(IFACE) -f $(TARGET_CFG) \
		-c "set TARGET stm32f4x; set DRY_RUN 1" \
		-f tcl/jtag_audit.tcl -c exit

# =============================================================================
# Modules kernel C (LiME + MSR reader)
# =============================================================================

## Compiler les modules kernel
kernel-modules:
ifeq ($(UNAME), Linux)
	@echo "[*] Compilation des modules kernel..."
	$(MAKE) -C c/kernel/
	@echo "[✓] Modules compilés : c/kernel/lime_wrapper.ko  c/kernel/msr_reader.ko"
else
	@echo "[!] Modules kernel disponibles uniquement sur Linux."
endif

## Charger les modules kernel (root requis)
kernel-install: kernel-modules
ifeq ($(UNAME), Linux)
	@echo "[!] Chargement des modules kernel (root requis)..."
	$(MAKE) -C c/kernel/ install
else
	@echo "[!] Modules kernel disponibles uniquement sur Linux."
endif

## Décharger les modules kernel
kernel-unload:
ifeq ($(UNAME), Linux)
	$(MAKE) -C c/kernel/ unload
endif

## Nettoyer les modules kernel
kernel-clean:
ifeq ($(UNAME), Linux)
	$(MAKE) -C c/kernel/ clean
endif

# =============================================================================
# Aide
# =============================================================================

help:
	@echo ""
	@echo "  ┌─────────────────────────────────────────────────────────────────┐"
	@echo "  │  Nevelio Hardware Security — Guide de lancement                │"
	@echo "  └─────────────────────────────────────────────────────────────────┘"
	@echo ""
	@echo "  Plateforme : $(UNAME) / $(ARCH)"
ifeq ($(UNAME), Linux)
	@echo "  eBPF       : activé (--features ebpf)"
else
	@echo "  eBPF       : désactivé (Linux uniquement)"
endif
	@echo ""
	@echo "  ── Initialisation ──────────────────────────────────────────────────"
	@echo "  make install-deps         Installer les dépendances système"
	@echo "  make build-release        Compiler en release (défaut : make)"
	@echo ""
	@echo "  ── Audit passif (sans root) ────────────────────────────────────────"
	@echo "  make run                  Audit texte stdout"
	@echo "  make run-html             Rapport HTML  → $(REPORT)"
	@echo "  make run-json             Rapport JSON  → stdout"
	@echo "  make run-target TARGET_URL=https://...   Timing oracle HTTP"
	@echo ""
	@echo "  ── Audit actif (root + eBPF) ───────────────────────────────────────"
	@echo "  make run-active           Audit complet (flashrom, eBPF)"
	@echo "  make run-active-html      Audit actif → rapport HTML"
	@echo ""
	@echo "  ── Modules ─────────────────────────────────────────────────────────"
	@echo "  make modules              Lister les modules"
	@echo "  make module-show MODULE=hw-cpu   Détail d'un module"
	@echo ""
	@echo "  ── Analyse firmware (Python) ───────────────────────────────────────"
	@echo "  make run-firmware FIRMWARE=/path/to/fw.bin"
	@echo "  make run-firmware-json FIRMWARE=/path/to/fw.bin REPORT=out.json"
	@echo ""
	@echo "  ── Audit JTAG (OpenOCD + Tcl) ─────────────────────────────────────"
	@echo "  make run-jtag IFACE=interface/ftdi/ft2232h.cfg TARGET_CFG=target/stm32f4x.cfg"
	@echo ""
	@echo "  ── Modules kernel C ────────────────────────────────────────────────"
	@echo "  make kernel-modules       Compiler lime_wrapper.ko + msr_reader.ko"
	@echo "  make kernel-install       Compiler + charger (root requis)"
	@echo "  make kernel-unload        Décharger les modules"
	@echo "  make kernel-clean         Nettoyer les .ko"
	@echo ""
	@echo "  ── Développement ───────────────────────────────────────────────────"
	@echo "  make test                 Tests unitaires"
	@echo "  make check                Clippy"
	@echo "  make clean                Nettoyer les artefacts Rust"
	@echo ""
	@echo "  Variables :"
	@echo "    REPORT=fichier.html     Chemin du rapport HTML (défaut: $(REPORT))"
	@echo "    TARGET_URL=https://...  URL cible pour le timing oracle"
	@echo "    FIRMWARE=/path/fw.bin   Chemin vers l'image firmware"
	@echo "    IFACE=cfg               Interface OpenOCD"
	@echo "    TARGET_CFG=cfg          Target OpenOCD"
	@echo ""
