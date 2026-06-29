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
        run-html run-json run-target modules test check clean help

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
		msr-tools
	@echo ""
	@echo "[✓] Dépendances système installées."
	@echo "[*] Pour Fedora/RHEL : sudo dnf install dmidecode mokutil efibootmgr fwupd flashrom pciutils clang llvm libbpf-devel bpftool checksec"
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
	@echo "  ── Développement ───────────────────────────────────────────────────"
	@echo "  make test                 Tests unitaires"
	@echo "  make check                Clippy"
	@echo "  make clean                Nettoyer les artefacts"
	@echo ""
	@echo "  Variables :"
	@echo "    REPORT=fichier.html     Chemin du rapport HTML (défaut: $(REPORT))"
	@echo "    TARGET_URL=https://...  URL cible pour le timing oracle"
	@echo ""
