# Nevelio — API Penetration Testing Tool

[![CI](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/ci.yml/badge.svg)](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/ci.yml)
[![Release](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/release.yml/badge.svg)](https://github.com/LordPhenixDeNetra/nevelio/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> **LEGAL NOTICE** — Use Nevelio only on systems you own or have explicit written
> authorization to test. Unauthorized use is illegal. See [Legal](#legal).

Nevelio is a fast, modular API security scanner written in Rust. It detects
vulnerabilities in REST and GraphQL APIs from an OpenAPI spec or a bare URL,
and produces actionable reports in JSON, HTML, Markdown, JUnit XML and SARIF formats.

---

## Features

| Module | Checks |
|---|---|
| `auth` | JWT alg:none bypass, weak secrets, claims manipulation, missing auth, Basic Auth brute force |
| `injection` | SQLi (boolean/time/union/error), NoSQLi (MongoDB operators), SSTI, Command Injection |
| `access-control` | IDOR (numeric + UUID), BFLA, vertical privilege escalation, mass assignment |
| `graphql` | Introspection exposure, field suggestions, depth-based DoS |
| `business-logic` | Rate limit bypass (XFF/UA rotation), race conditions, negative values, price manipulation |
| `infra` | CORS, HSTS, CSP, TLS, cookie flags, secrets in responses, stack traces, 20+ debug endpoints |

Nevelio also ships **`nevelio-hw`**, a companion binary for hardware-layer security
audits — see [Hardware Security Extension](#hardware-security-extension-nevelio-hw).

---

## Installation

### Debian / Ubuntu — apt

> Requires GitHub Pages enabled on the `packages` branch of the repository.

```bash
# 1. Add the GPG signing key
curl -fsSL https://lordphenixdenetra.github.io/nevelio/apt/KEY.gpg \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/nevelio.gpg

# 2. Add the repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/trusted.gpg.d/nevelio.gpg] \
  https://lordphenixdenetra.github.io/nevelio/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nevelio.list

# 3. Install
sudo apt update && sudo apt install nevelio
```

Or install directly from a `.deb` file (no repo needed):

```bash
ARCH=$(dpkg --print-architecture)  # amd64 or arm64
curl -LO https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio_latest_${ARCH}.deb
sudo dpkg -i nevelio_latest_${ARCH}.deb
```

### RHEL / CentOS / Fedora — yum / dnf

> Requires GitHub Pages enabled on the `packages` branch of the repository.

```bash
# 1. Add the GPG key
sudo rpm --import https://lordphenixdenetra.github.io/nevelio/rpm/RPM-GPG-KEY-nevelio

# 2. Add the repository
sudo tee /etc/yum.repos.d/nevelio.repo << 'EOF'
[nevelio]
name=Nevelio — API Security Scanner
baseurl=https://lordphenixdenetra.github.io/nevelio/rpm/$basearch
enabled=1
gpgcheck=1
gpgkey=https://lordphenixdenetra.github.io/nevelio/rpm/RPM-GPG-KEY-nevelio
EOF

# 3. Install
sudo dnf install nevelio   # Fedora / RHEL 8+
sudo yum install nevelio   # CentOS 7
```

Or install directly from an `.rpm` file (no repo needed):

```bash
ARCH=$(uname -m)  # x86_64 or aarch64
curl -LO https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio_latest_${ARCH}.rpm
sudo rpm -i nevelio_latest_${ARCH}.rpm
```

### macOS and Linux — Homebrew

```bash
brew tap LordPhenixDeNetra/nevelio
brew install nevelio
```

### Windows — winget

```powershell
winget install LordPhenixDeNetra.nevelio
```

### Linux / macOS — Script universel

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio-installer.sh \
  | sh
```

### Windows — PowerShell

```powershell
irm https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio-installer.ps1 | iex
```

### Docker

```bash
docker pull lordphenixdenetra/nevelio:latest
docker run --rm lordphenixdenetra/nevelio:latest --version
```

### Binaires pré-compilés (GitHub Releases)

Téléchargez l'archive correspondant à votre plateforme depuis la
[page Releases](https://github.com/LordPhenixDeNetra/nevelio/releases/latest) :

| Plateforme | Archive |
|---|---|
| Linux x86_64 (musl) | `nevelio-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (musl) | `nevelio-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `nevelio-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `nevelio-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `nevelio-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

### Depuis les sources (Rust requis ≥ 1.75)

```bash
git clone https://github.com/LordPhenixDeNetra/nevelio.git
cd nevelio
cargo build --release
cp target/release/nevelio /usr/local/bin/   # Linux/macOS
```

---

## Usage

### Disclaimer légal (premier lancement)

Au premier scan, Nevelio affiche un avertissement et demande confirmation.
Pour CI/CD, utilisez `--accept-legal` ou la variable `NEVELIO_ACCEPT_LEGAL=1` :

```bash
nevelio --accept-legal scan --url https://api.example.com --dry-run
```

### Scan depuis une spec OpenAPI

```bash
nevelio --accept-legal scan \
  --spec openapi.yaml \
  --target https://staging.api.example.com \
  --output html \
  --out-dir ./reports
```

### Scan sans spec (auto-discovery)

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --module auth injection
```

### Scan authentifié

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --auth-token "Bearer eyJhbGci..."
```

### Via un proxy (Burp Suite)

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --proxy http://127.0.0.1:8080
```

### Dry-run (aucune requête réelle)

```bash
nevelio --accept-legal scan --url https://api.example.com --dry-run
```

### Via Docker

```bash
docker run --rm \
  -v $(pwd)/openapi.yaml:/spec.yaml \
  -v $(pwd)/reports:/reports \
  lordphenixdenetra/nevelio:latest \
  --accept-legal scan \
  --spec /spec.yaml \
  --target https://staging.api.example.com \
  --output html \
  --out-dir /reports
```

---

## Internationalisation (`--lang`)

Nevelio supporte **3 langues** — français (`fr`), anglais (`en`), espagnol (`es`).

```bash
nevelio --lang en scan --url https://api.example.com --accept-legal
nevelio --lang es scan --url https://api.example.com --accept-legal
NEVELIO_LANG=fr nevelio scan --url https://api.example.com --accept-legal
```

Priorité de détection : `--lang` > `NEVELIO_LANG` > `$LANG` > anglais par défaut.

---

## CLI Reference

### Global flags

| Flag | Description |
|---|---|
| `--accept-legal` | Accepter le disclaimer sans prompt interactif |
| `--lang <LANG>` | Langue : `fr` / `en` / `es` |
| `--verbose` | Logs détaillés et requêtes HTTP |
| `--no-color` | Désactiver les couleurs ANSI |

### `scan`

| Flag | Default | Description |
|---|---|---|
| `--url <URL>` | — | URL de base de l'API cible |
| `--target <URL>` | — | Alias de `--url` |
| `--spec <SPEC>` | — | Fichier ou URL OpenAPI/Swagger (JSON ou YAML) |
| `--profile` | `normal` | `stealth` / `normal` / `aggressive` |
| `--module <NAME>` | tous | Restreindre à un ou plusieurs modules |
| `--output <FORMAT>` | `html` | `json` / `html` / `markdown` / `junit` / `sarif` |
| `--out-dir <PATH>` | `.` | Répertoire de sortie |
| `--auth-token <TOKEN>` | — | Header Authorization complet |
| `--proxy <URL>` | — | Proxy HTTP/S |
| `--concurrency <N>` | profil | Requêtes simultanées |
| `--rate-limit <N>` | profil | Requêtes par seconde |
| `--timeout <SECS>` | `10` | Timeout par requête |
| `--fail-on <SEV>` | — | Seuil CI : `none` / `low` / `medium` / `high` / `critical` |
| `--dry-run` | false | Simuler sans requêtes réelles |
| `--resume` | false | Reprendre un scan interrompu |
| `--no-tui` | false | Désactiver le dashboard TUI |
| `--ai-suggestions` | false | Suggestions IA (nécessite `ANTHROPIC_API_KEY`) |

### `report` / `convert`

Re-génère un rapport depuis un `findings.json` existant, sans relancer le scan :

```bash
nevelio --accept-legal report \
  --input findings.json \
  --format sarif \
  --out-dir ./security
```

### `modules`

```bash
nevelio modules list
nevelio modules show auth
nevelio modules show injection
```

---

## Profils de scan

| Profil | Concurrence | Rate limit | Usage recommandé |
|---|---|---|---|
| `stealth` | 1 | 2 req/s | Production sensible |
| `normal` | 5 | 10 req/s | Staging (défaut) |
| `aggressive` | 20 | 50 req/s | Lab / environnement dédié |

---

## Formats de sortie

| Format | Fichier | Usage |
|---|---|---|
| `json` | `findings.json` | Source canonique, SIEM, Jira |
| `html` | `report.html` | Rapport interactif avec filtres et thème |
| `markdown` | `report.md` | PRs GitHub, wikis, Confluence |
| `junit` | `report.xml` | GitHub Actions, GitLab CI, Jenkins |
| `sarif` | `report.sarif` | GitHub Advanced Security, CodeQL |

---

## CI/CD Integration

### Exit codes

| Code | Signification |
|---|---|
| `0` | Aucun finding (ou sous le seuil `--fail-on`) |
| `1` | Findings au-dessus du seuil |

### GitHub Actions

```yaml
- name: Run API Security Scan
  run: |
    nevelio scan \
      --target ${{ vars.API_STAGING_URL }} \
      --spec openapi.yaml \
      --output sarif \
      --out-dir sarif-results \
      --fail-on high \
      --accept-legal \
      --no-tui \
      --no-color

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sarif-results/report.sarif
```

Voir le workflow complet : [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)

### GitLab CI

```yaml
api-security-scan:
  stage: test
  image: lordphenixdenetra/nevelio:latest
  script:
    - nevelio scan --target "$API_STAGING_URL" --spec openapi.yaml
        --output junit --out-dir results --fail-on high
        --accept-legal --no-tui --no-color
  artifacts:
    reports:
      junit: results/report.xml
```

---

## Environnements de test

Démarrez des cibles vulnérables localement :

```bash
docker compose up -d
```

| Cible | URL | Description |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | API Node.js riche en vulnérabilités |
| VAmPI | http://localhost:5000 | REST API vulnérable (OWASP API Top 10) |
| DVWA | http://localhost:8080 | Application PHP vulnérable |
| crAPI | http://localhost:8888 | API automobile vulnérable (OWASP) |

```bash
# Exemple de scan contre Juice Shop
nevelio --accept-legal scan \
  --url http://localhost:3000 \
  --profile aggressive \
  --output html \
  --out-dir ./reports
```

---

## Hardware Security Extension (`nevelio-hw`)

`nevelio-hw` is a separate binary included in the `hardware/` workspace.
It audits the **hardware and kernel security layer** of a Linux machine :
CPU mitigations (Spectre/Meltdown/MDS), UEFI/Secure Boot, DMA/IOMMU/Thunderbolt,
timing side-channels, eBPF syscall latency, and more.

> **Requires Linux.** On macOS the binary compiles but most checks are silently skipped
> (no `/sys`, `/proc` or eBPF available).

### Modules

| Module | Checks |
|---|---|
| `hw-cpu` | Spectre v1/v2, Meltdown, MDS, L1TF, Retbleed, ASLR, KASLR, microcode, NX/SMEP |
| `hw-firmware` | UEFI Secure Boot, BIOS version/age, EFI Shell entries, flash SPI, fwupd updates |
| `hw-dma` | IOMMU (on/off/passthrough/strict), Thunderbolt security level, PCIe BusMaster, kernel lockdown |
| `hw-sidechannel` | Flush+Reload (CLFLUSH/RDTSC), HTTP timing oracle (CWE-208), perf_event_paranoid, ptrace_scope, eBPF latency |

### Build et lancement (tout en une commande)

```bash
# 1. Dépendances système (Linux, une seule fois)
cd hardware && make install-deps

# 2. Build (compile le binaire + les programmes eBPF si clang est disponible)
make

# 3. Audit passif complet (sans root)
make run

# 4. Audit actif : flashrom + eBPF (root requis)
sudo make run-active

# 5. Rapport HTML
make run-html REPORT=rapport.html

# 6. Timing oracle sur une API distante
make run-target TARGET_URL=https://api.example.com
```

### Cibles Makefile principales

| Commande | Description |
|---|---|
| `make install-deps` | Installe dmidecode, clang, libbpf-dev, bpftool, checksec… |
| `make` | Build release (active `--features ebpf` automatiquement sur Linux) |
| `make run` | Audit passif — stdout texte coloré |
| `make run-active` | Audit actif + eBPF (root requis) |
| `make run-html REPORT=f.html` | Rapport HTML dark-mode |
| `make run-json` | Rapport JSON → stdout |
| `make run-target TARGET_URL=…` | Timing oracle HTTP |
| `make test` | Tests unitaires |

### Depuis les sources

```bash
# Build seul (sans Makefile)
cd hardware
cargo build --release                        # macOS / dev
cargo build --release --features ebpf        # Linux avec eBPF
./target/release/nevelio-hw --help
```

### eBPF (Linux ≥ 5.4, root requis)

Les programmes eBPF (`syscall_latency`, `memory_access`) sont compilés
automatiquement par `build.rs` lors du `cargo build --features ebpf`
si `clang` est disponible. Ils sont **embarqués dans le binaire** via
`include_bytes!` — aucun fichier externe nécessaire à l'exécution.

```
make install-deps   # installe clang + libbpf-dev
make                # build + compile .bpf.c → .bpf.o → intégré dans nevelio-hw
sudo make run-active
```

Si `clang` est absent, un avertissement est émis et les checks eBPF sont
simplement désactivés — le reste de l'audit fonctionne normalement.

---

## Développement

```bash
# Build
cargo build --workspace

# Tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

---

## Architecture

```
nevelio/
├── crates/
│   ├── cli/                # Point d'entrée, CLI (clap), commandes
│   ├── core/               # Types, session, HttpClient, trait AttackModule
│   ├── modules/
│   │   ├── auth/           # JWT, Basic Auth, authentification manquante
│   │   ├── injection/      # SQLi, NoSQLi, SSTI, Command Injection
│   │   ├── access-control/ # IDOR, BFLA, élévation de privilèges, mass assignment
│   │   ├── graphql/        # Introspection, field suggestions, depth DoS
│   │   ├── business-logic/ # Rate limit, race conditions, manipulation de prix
│   │   └── infra/          # Headers, TLS, cookies, secrets, debug endpoints
│   ├── recon/              # Parseur OpenAPI, crawleur d'endpoints
│   └── reporting/          # Reporters JSON, HTML (Tera), Markdown, JUnit, SARIF
├── hardware/               # Extension sécurité hardware (workspace Cargo séparé)
│   ├── Makefile            # Point d'entrée unique : make / make run / make run-active
│   ├── crates/
│   │   ├── hw-core/        # Types HardwareFinding, HwModule, HwScanContext, HTML reporter
│   │   ├── hw-cpu/         # Mitigations CPU, ASLR, microcode
│   │   ├── hw-firmware/    # UEFI, Secure Boot, flash SPI
│   │   ├── hw-dma/         # IOMMU, Thunderbolt, PCIe, kernel lockdown
│   │   ├── hw-sidechannel/ # Flush+Reload, timing oracle, eBPF latence, checksec
│   │   └── hw-cli/         # Binaire nevelio-hw (clap, scan, modules)
│   ├── asm/
│   │   ├── x86_64/         # timing.asm — CLFLUSH + RDTSC (référence NASM)
│   │   └── aarch64/        # timing.asm — CNTVCT_EL0 + DC CIVAC (référence GAS)
│   └── ebpf/
│       ├── syscall_latency.bpf.c   # Tracer latence syscalls (ring buffer)
│       └── memory_access.bpf.c     # Détection accès mémoire / rowhammer
├── docs/                   # Documentation, cahier des charges, suivi des tâches
└── payloads/               # Bibliothèques de payloads YAML (sqli, jwt, idor)
```

---

## Legal

> Nevelio is intended exclusively for security testing on systems you own or
> have explicit written authorization to test.

1. Vous devez disposer d'une **autorisation écrite** du propriétaire du système avant tout scan.
2. Ne pas utiliser sur des systèmes de production sans accord formel de pentest.
3. Toute vulnérabilité découverte sur un système tiers doit être signalée via une **Responsible Disclosure**.
4. Les auteurs déclinent toute responsabilité en cas d'utilisation non autorisée.

**Références légales :** CFAA (US), Computer Misuse Act (UK), Directive NIS2 (EU), LCEN (FR).

