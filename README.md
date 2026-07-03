# Nevelio

[![CI](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/ci.yml/badge.svg)](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/ci.yml)
[![Release](https://github.com/LordPhenixDeNetra/nevelio/actions/workflows/release.yml/badge.svg)](https://github.com/LordPhenixDeNetra/nevelio/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75-orange.svg)](https://www.rust-lang.org)

**Fast, modular API security scanner written in Rust.**  
Detects vulnerabilities in REST and GraphQL APIs — from an OpenAPI spec or a bare URL —
and produces actionable reports in JSON, HTML, Markdown, JUnit XML and SARIF.

> **LEGAL NOTICE** — Use Nevelio only on systems you own or for which you hold
> explicit written authorisation. Unauthorised use is illegal in every jurisdiction.
> See [Legal](#legal).

---

## What Nevelio does

| Command | Purpose |
|---|---|
| `nevelio scan` | Run 70+ security checks across 6 attack modules |
| `nevelio agent` | Autonomous LLM-driven audit loop (discover → probe → report) |
| `nevelio mcp serve` | Expose Nevelio tools to Claude Desktop / any MCP-compatible agent |
| `nevelio config` | Manage AI provider configuration (Anthropic, OpenAI, Mistral, Groq, Ollama, Bedrock) |
| `nevelio report` | Convert an existing `findings.json` to any output format without re-scanning |
| `nevelio diff` | Compare two scan results and highlight regressions |
| `nevelio watch` | Watch mode — re-scan automatically on spec change |

---

## Attack modules

| Module | Checks |
|---|---|
| `auth` | JWT alg:none bypass, weak secret brute force, claims manipulation, missing auth, Basic Auth brute force |
| `injection` | SQLi (boolean / time / union / error), NoSQLi (MongoDB operators), SSTI, command injection |
| `access-control` | Numeric + UUID IDOR, BFLA, vertical privilege escalation, mass assignment |
| `graphql` | Introspection exposure, field suggestions, depth-based DoS |
| `business-logic` | Rate-limit bypass (XFF / UA rotation), race conditions, negative values, price manipulation |
| `infra` | CORS, HSTS, CSP, TLS 1.0/1.1, cookie flags, secrets in responses, stack traces, 20+ debug endpoints |

---

## Quick start

```bash
# 1. First-run legal confirmation (persisted to ~/.config/nevelio/legal_accepted)
nevelio --accept-legal scan --target https://api.example.com --dry-run

# 2. Full scan with HTML report
nevelio --accept-legal scan \
  --target https://staging.api.example.com \
  --spec openapi.yaml \
  --output html \
  --out-dir ./reports

# 3. Scan specific modules only
nevelio --accept-legal scan \
  --target https://api.example.com \
  --module auth injection access-control
```

---

## Installation

### Debian / Ubuntu

```bash
curl -fsSL https://lordphenixdenetra.github.io/nevelio/apt/KEY.gpg \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/nevelio.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/trusted.gpg.d/nevelio.gpg] \
  https://lordphenixdenetra.github.io/nevelio/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nevelio.list

sudo apt update && sudo apt install nevelio
```

### RHEL / Fedora / CentOS

```bash
sudo rpm --import https://lordphenixdenetra.github.io/nevelio/rpm/RPM-GPG-KEY-nevelio

sudo tee /etc/yum.repos.d/nevelio.repo << 'EOF'
[nevelio]
name=Nevelio — API Security Scanner
baseurl=https://lordphenixdenetra.github.io/nevelio/rpm/$basearch
enabled=1
gpgcheck=1
gpgkey=https://lordphenixdenetra.github.io/nevelio/rpm/RPM-GPG-KEY-nevelio
EOF

sudo dnf install nevelio
```

### macOS / Linux — Homebrew

```bash
brew tap LordPhenixDeNetra/nevelio
brew install nevelio
```

### Windows — winget

```powershell
winget install LordPhenixDeNetra.nevelio
```

### Universal installer

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio-installer.sh | sh

# Windows PowerShell
irm https://github.com/LordPhenixDeNetra/nevelio/releases/latest/download/nevelio-installer.ps1 | iex
```

### Docker

```bash
docker pull lordphenixdenetra/nevelio:latest
docker run --rm \
  -v $(pwd)/openapi.yaml:/spec.yaml \
  -v $(pwd)/reports:/reports \
  lordphenixdenetra/nevelio:latest \
  --accept-legal scan --spec /spec.yaml \
  --target https://staging.api.example.com \
  --output html --out-dir /reports
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/LordPhenixDeNetra/nevelio/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86_64 (musl) | `nevelio-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (musl) | `nevelio-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `nevelio-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `nevelio-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `nevelio-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

### From source (Rust ≥ 1.75)

```bash
git clone https://github.com/LordPhenixDeNetra/nevelio.git
cd nevelio
cargo build --release
cp target/release/nevelio ~/.local/bin/
```

---

## Usage

### Scan profiles

| Profile | Concurrency | Rate | Recommended for |
|---|---|---|---|
| `stealth` | 1 req | 2 req/s | Sensitive production systems |
| `normal` | 5 reqs | 10 req/s | Staging (default) |
| `aggressive` | 20 reqs | 50 req/s | Dedicated lab / isolated env |

```bash
nevelio --accept-legal scan --target https://api.example.com --profile stealth
```

### Authenticated scan

```bash
# Static token
nevelio --accept-legal scan \
  --target https://api.example.com \
  --auth-token "Bearer eyJhbGci..."

# Token from environment variable (recommended — avoids shell history exposure)
AUTH_TOKEN_ENV=API_TOKEN nevelio --accept-legal scan --target https://api.example.com
```

### Via proxy (Burp Suite)

```bash
nevelio --accept-legal scan \
  --target https://api.example.com \
  --proxy http://127.0.0.1:8080
```

### Input formats (auto-detected)

```bash
# OpenAPI 3.x / Swagger 2 (JSON or YAML)
nevelio --accept-legal scan --spec openapi.yaml --target https://api.example.com

# Postman v2.1 collection
nevelio --accept-legal scan --spec collection.postman_json --target https://api.example.com

# Insomnia v4 export
nevelio --accept-legal scan --spec insomnia.json --target https://api.example.com

# HAR (HTTP Archive)
nevelio --accept-legal scan --spec traffic.har --target https://api.example.com
```

---

## AI features

Nevelio integrates multi-provider AI capabilities. Configure a provider once, then use any combination of flags.

### Configure a provider

```bash
# Interactive wizard (Anthropic, OpenAI, Mistral, Groq, Ollama, AWS Bedrock)
nevelio config init

# Verify connectivity
nevelio config ai ping

# Or use environment variables directly
export ANTHROPIC_API_KEY=sk-ant-api03-...   # Anthropic
export OPENAI_API_KEY=sk-...                # OpenAI
export MISTRAL_API_KEY=...                  # Mistral
export GROQ_API_KEY=gsk_...                 # Groq
# Ollama: no key needed (local)
# Bedrock: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION
```

### AI scan flags

| Flag | Output file | Description |
|---|---|---|
| `--ai-triage` | `ai_triage.json` | Classify each finding: true positive / false positive / uncertain |
| `--ai-remediation` | `ai_remediation.md` | Step-by-step remediation with code examples |
| `--ai-report` | `ai_narrative_report.md` | Full executive report with attack chain narrative |
| `--ai-payloads` | `ai_payloads.json` | Context-aware attack payloads tailored to the target |

```bash
# All AI flags at once
nevelio --accept-legal scan \
  --target https://api.example.com \
  --ai-triage --ai-remediation --ai-report --ai-payloads \
  --out-dir ./results
```

### Per-task provider routing

Route each AI task to a different provider in `~/.config/nevelio/config.toml`:

```toml
[ai.routing]
triage      = "groq"       # fast for triage
report      = "anthropic"  # quality writing for reports
payloads    = "ollama"     # local, no cost
fallback    = "openai"     # if primary provider is unavailable
```

---

## Autonomous agent

The agent drives a **LLM → tools → analysis** loop autonomously:
discover endpoints, probe them, identify vulnerabilities, produce a report.

```bash
nevelio agent https://api.example.com \
  --max-iterations 15 \
  --max-requests 200 \
  --ai-budget 50000 \
  --out-dir ./agent-report \
  --accept-legal

# Dry run — plan without sending real HTTP requests
nevelio agent https://api.example.com --dry-run --max-iterations 5 --accept-legal
```

**Built-in guardrails:** scope enforcement (refuses out-of-target requests), request cap,
token budget cap, dry-run mode, `--accept-legal` gate.

---

## MCP server

Expose Nevelio tools to Claude Desktop, Continue.dev, or any MCP-compatible orchestrator.

```bash
nevelio mcp serve --target https://api.example.com --accept-legal
```

**Claude Desktop configuration** (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nevelio": {
      "command": "nevelio",
      "args": ["mcp", "serve", "--target", "https://api.example.com", "--accept-legal"]
    }
  }
}
```

Available tools: `list_endpoints`, `probe_endpoint`, `report_finding`, `finish`.  
Transport: **stdio** — MCP protocol version `2024-11-05`.

---

## Output formats

| Format | File | Use case |
|---|---|---|
| `json` | `findings.json` | Canonical source — always written. SIEM, Jira, custom pipelines |
| `html` | `report.html` | Interactive report with severity filters and dark/light theme |
| `markdown` | `report.md` | GitHub PRs, wikis, Confluence |
| `junit` | `security-report.xml` | GitHub Actions, GitLab CI, Jenkins |
| `sarif` | `security-report.sarif` | GitHub Advanced Security, CodeQL |

Convert an existing `findings.json` without re-scanning:

```bash
nevelio --accept-legal report --input findings.json --format sarif --out-dir ./security
```

---

## CI/CD

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings (or below `--fail-on` threshold) |
| `1` | Findings at or above threshold |
| `2` | High severity findings present |
| `3` | Critical severity findings present |

### GitHub Actions

```yaml
- name: API Security Scan
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    nevelio scan \
      --target ${{ vars.API_STAGING_URL }} \
      --spec openapi.yaml \
      --output sarif \
      --out-dir sarif-results \
      --fail-on high \
      --ai-triage \
      --accept-legal --no-tui --no-color

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sarif-results/security-report.sarif
```

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
      junit: results/security-report.xml
```

---

## Internationalisation

Nevelio CLI, TUI, legal disclaimer and AI prompts are available in **3 languages**:
French (`fr`), English (`en`), Spanish (`es`).

Detection order: `--lang` flag > `NEVELIO_LANG` env var > `$LANG` system variable > English default.

```bash
nevelio --lang fr scan --target https://api.example.com --accept-legal
NEVELIO_LANG=es nevelio scan --target https://api.example.com --accept-legal
```

---

## CLI reference

### Global flags

| Flag | Description |
|---|---|
| `--accept-legal` | Accept legal disclaimer without interactive prompt |
| `--lang <LANG>` | Language: `fr` / `en` / `es` |
| `--verbose` | Detailed logs and HTTP requests |
| `--no-color` | Disable ANSI colours (CI logs) |

### `scan` flags

| Flag | Default | Description |
|---|---|---|
| `--target <URL>` | — | Base URL of the target API |
| `--spec <PATH>` | — | OpenAPI / Postman / Insomnia / HAR (auto-detected) |
| `--profile` | `normal` | `stealth` / `normal` / `aggressive` |
| `--module <NAME>…` | all | Restrict to one or more modules |
| `--output <FORMAT>` | `html` | `json` / `html` / `markdown` / `junit` / `sarif` |
| `--out-dir <PATH>` | `.` | Output directory |
| `--auth-token <TOKEN>` | — | Full Authorization header value |
| `--proxy <URL>` | — | HTTP/S proxy |
| `--concurrency <N>` | profile | Concurrent requests |
| `--rate-limit <N>` | profile | Requests per second |
| `--timeout <SECS>` | `10` | Per-request timeout |
| `--fail-on <SEV>` | — | CI exit threshold: `none` / `low` / `medium` / `high` / `critical` |
| `--dry-run` | false | Plan without sending real requests |
| `--resume` | false | Resume an interrupted scan from `--out-dir` |
| `--no-tui` | false | Disable TUI dashboard |
| `--ai-triage` | false | AI triage of findings (requires configured provider) |
| `--ai-remediation` | false | AI remediation steps |
| `--ai-report` | false | AI executive narrative report |
| `--ai-payloads` | false | AI contextual attack payloads |

### Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `MISTRAL_API_KEY` | Mistral AI API key |
| `GROQ_API_KEY` | Groq API key |
| `AWS_ACCESS_KEY_ID` | AWS credentials (Bedrock provider) |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials (Bedrock provider) |
| `AWS_SESSION_TOKEN` | AWS temporary session token (optional) |
| `AWS_REGION` | AWS region for Bedrock |
| `NEVELIO_LANG` | Force language without CLI flag |
| `NEVELIO_ACCEPT_LEGAL` | Set to `1` to skip legal prompt |

---

## Architecture

```
nevelio/
├── crates/
│   ├── cli/               # Entry point, CLI (clap), command routing
│   ├── core/              # Types, session, HttpClient, AttackModule trait
│   ├── nevelio-config/    # Global + project config, semantic validation, merge
│   ├── nevelio-ai/        # Multi-provider AI (Anthropic, OpenAI, Mistral, Groq, Ollama, Bedrock)
│   ├── modules/
│   │   ├── auth/          # JWT, Basic Auth, missing authentication
│   │   ├── injection/     # SQLi, NoSQLi, SSTI, command injection
│   │   ├── access-control/# IDOR, BFLA, privilege escalation, mass assignment
│   │   ├── graphql/       # Introspection, field suggestions, depth DoS
│   │   ├── business-logic/# Rate limit bypass, race conditions, price manipulation
│   │   └── infra/         # Headers, TLS, cookies, secrets, debug endpoints
│   ├── recon/             # OpenAPI / Postman / Insomnia / HAR parsers, JS crawler
│   └── reporting/         # JSON, HTML (Tera), Markdown, JUnit, SARIF reporters
├── hardware/              # nevelio-hw — hardware security extension (separate workspace)
├── docs/                  # Web documentation, tutorial, task tracking
└── payloads/              # YAML payload libraries (sqli, jwt, idor, cmdi)
```

---

## Hardware Security Extension (`nevelio-hw`)

A companion binary that audits the **hardware and kernel security layer** of a Linux machine.

| Module | Checks |
|---|---|
| `hw-cpu` | Spectre v1/v2, Meltdown, MDS, Retbleed, ASLR/KASLR, microcode, NX/SMEP/SMAP |
| `hw-firmware` | UEFI Secure Boot, BIOS age, EFI Shell entries, SPI flash, fwupd updates |
| `hw-dma` | IOMMU/VT-d, Thunderbolt security level, PCIe BusMaster, kernel lockdown |
| `hw-sidechannel` | Flush+Reload (CLFLUSH/RDTSC), HTTP timing oracle (CWE-208), eBPF latency |
| `hw-jtag` | JTAG/UART probe detection, STM32 RDP Level 0, firmware analysis (binwalk + angr) |
| `hw-memory` | Rowhammer, ECC/TRR, swap+KASLR, Volatility forensics (DKOM, malfind) |
| `hw-dma-fpga` | IOMMU strict mode, leechcore FFI, Verilog PCIe TLP injection |

```bash
cd hardware
make install-deps   # clang, libbpf-dev, dmidecode, checksec (Linux only, once)
make                # build release + compile eBPF programs
make run            # passive audit (no root needed)
sudo make run-active  # active audit + eBPF (root required)
make run-html REPORT=audit.html
```

> Requires Linux. On macOS the binary compiles but most checks are silently skipped.

---

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all
```

### Local test targets (Docker Compose)

```bash
docker compose up -d
```

| Target | URL | Description |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Node.js API, intentionally vulnerable |
| VAmPI | http://localhost:5000 | REST API (OWASP API Top 10) |
| crAPI | http://localhost:8888 | Automotive API (OWASP) |
| DVWA | http://localhost:8080 | PHP vulnerable web app |

---

## Legal

Nevelio is designed exclusively for authorised security testing.

1. You must hold **explicit written authorisation** from the system owner before any scan.
2. Do not run against production systems without a formal penetration testing agreement.
3. Any vulnerability discovered on a third-party system must be reported via **Responsible Disclosure**.
4. The authors accept no liability for unauthorised use.

**Legal references:** CFAA (US) · Computer Misuse Act (UK) · Directive NIS2 (EU) · LCEN (FR) · CP 323-1/323-8 (FR).
