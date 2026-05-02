# Nevelio — API Penetration Testing Tool

> **LEGAL NOTICE** — Use Nevelio only on systems you own or have explicit written
> authorization to test. Unauthorized use is illegal. See [Legal](#legal).

Nevelio is a fast, modular API security scanner written in Rust. It detects
vulnerabilities in REST APIs from an OpenAPI spec or a bare URL, and produces
actionable reports in JSON, HTML, Markdown, and JUnit XML formats.

---

## Features

| Module | Checks |
|---|---|
| `auth` | JWT alg:none bypass, weak secrets, claims manipulation, missing auth, Basic Auth brute force |
| `injection` | SQLi (boolean/time/union/error), NoSQLi (MongoDB operators), SSTI, Command Injection |
| `access-control` | IDOR (numeric + UUID), BFLA, vertical privilege escalation, mass assignment |
| `business-logic` | Rate limit bypass (XFF/UA rotation), race conditions, negative values, price manipulation |
| `infra` | CORS, HSTS, CSP, TLS/HTTP, cookie flags, Referrer-Policy, secrets in responses, stack traces, debug endpoints |

---

## Installation

### From source

```bash
git clone https://github.com/your-org/nevelio.git
cd nevelio
cargo build --release
cp target/release/nevelio /usr/local/bin/
```

### Docker

```bash
docker pull nevelio/nevelio:latest

# or build locally
docker build -t nevelio/nevelio:dev .
```

---

## Usage

### Accept the legal disclaimer

All commands require `--accept-legal` (or interactive confirmation on first run):

```bash
nevelio --accept-legal <subcommand>
```

### Scan from an OpenAPI spec

```bash
nevelio --accept-legal scan \
  --spec openapi.yaml \
  --target https://staging.api.example.com \
  --output html \
  --out-dir ./reports
```

### Scan from a URL (auto-discovery)

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --module auth \
  --module injection
```

### Authenticated scan

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --auth-token "Bearer eyJhbGci..."
```

### Via a proxy (Burp Suite)

```bash
nevelio --accept-legal scan \
  --url https://api.example.com \
  --proxy http://127.0.0.1:8080
```

### Dry-run (no real HTTP requests)

```bash
nevelio --accept-legal scan --url https://api.example.com --dry-run
```

### Docker usage

```bash
docker run --rm \
  -v $(pwd)/openapi.yaml:/spec.yaml \
  -v $(pwd)/reports:/reports \
  nevelio/nevelio:latest \
  --accept-legal scan \
  --spec /spec.yaml \
  --target https://staging.api.example.com \
  --output html \
  --out-dir /reports
```

---

## CLI Reference

### `scan`

| Flag | Default | Description |
|---|---|---|
| `--url <URL>` | — | Base URL of the target API |
| `--spec <SPEC>` | — | Path or URL to an OpenAPI/Swagger spec |
| `--target <URL>` | — | Alias for `--url` when used with `--spec` |
| `--profile` | `normal` | `stealth` / `normal` / `aggressive` |
| `--module <NAME>` | all | Restrict to specific module(s) |
| `--output <FORMAT>` | `json` | `json` / `html` / `markdown` / `junit` |
| `--out-dir <PATH>` | `.` | Directory for output files |
| `--auth-token <TOKEN>` | — | `Bearer <jwt>` or `Basic <b64>` |
| `--proxy <URL>` | — | HTTP/S proxy (e.g. Burp Suite) |
| `--concurrency <N>` | profile | Override max concurrent requests |
| `--rate-limit <N>` | profile | Override requests per second |
| `--timeout <SECS>` | `5` | Request timeout in seconds |
| `--dry-run` | false | Simulate without real requests |
| `--verbose` | false | Enable debug logging |

### `report`

Re-generate a report from an existing `findings.json`:

```bash
nevelio --accept-legal report \
  --input findings.json \
  --format html \
  --out-dir ./reports
```

### `modules`

```bash
nevelio --accept-legal modules list
nevelio --accept-legal modules show auth
```

---

## Output Formats

| Format | File | Use case |
|---|---|---|
| `json` | `findings.json` | Machine-readable, SIEM/Jira ingestion |
| `html` | `report.html` | Interactive report with severity filters |
| `markdown` | `report.md` | GitHub PRs, wikis |
| `junit` | `security-report.xml` | GitHub Actions / GitLab CI / Jenkins |

---

## CI/CD Integration

### Exit codes

| Code | Meaning | Pipeline behavior |
|---|---|---|
| `0` | No findings | Continue |
| `1` | Low / Medium findings | Continue (warning) |
| `2` | High findings | Configurable fail |
| `3` | Critical findings | Automatic fail |

### GitHub Actions

Copy [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)
into your project and set these secrets:

- `API_STAGING_URL` — base URL of your staging API
- `API_TOKEN` — authentication token (optional)

### GitLab CI

Copy [`.gitlab-ci.yml`](.gitlab-ci.yml) and set CI/CD variables:
`API_STAGING_URL`, `API_TOKEN`.

---

## Scan Profiles

| Profile | Concurrency | Rate limit |
|---|---|---|
| `stealth` | 5 | 10 req/s |
| `normal` | 20 | 50 req/s |
| `aggressive` | 100 | 200 req/s |

---

## Test Environments

Start vulnerable test targets locally:

```bash
docker compose up -d
```

| Target | URL | Description |
|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | Rich vulnerable Node.js API |
| VAmPI | http://localhost:5000 | Vulnerable REST API (OWASP) |
| DVWA | http://localhost:8080 | PHP vulnerable web application |

Example scan against Juice Shop:

```bash
nevelio --accept-legal scan \
  --url http://localhost:3000 \
  --profile aggressive \
  --output html \
  --out-dir ./reports
```

---

## Development

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
│   ├── cli/               # Entry point, CLI (clap), commands
│   ├── core/              # Types, session, HttpClient, AttackModule trait
│   ├── modules/
│   │   ├── auth/          # JWT, Basic Auth, missing authentication
│   │   ├── injection/     # SQLi, NoSQLi, SSTI, Command Injection
│   │   ├── access-control/# IDOR, BFLA, privilege escalation, mass assignment
│   │   ├── business-logic/# Rate limit, race conditions, price manipulation
│   │   └── infra/         # Headers, TLS, cookies, secrets, debug endpoints
│   ├── recon/             # OpenAPI parser, endpoint crawler, header analyzer
│   └── reporting/         # JSON, HTML (Tera), Markdown, JUnit reporters
└── payloads/              # YAML payload libraries (sqli, jwt, idor)
```

---

## Legal

> Nevelio is intended exclusively for security testing on systems you own or
> have explicit written authorization to test.

1. You must have written authorization from the system owner before scanning.
2. Do not use on production systems without a formal pentest agreement.
3. Any vulnerability discovered on third-party systems must be reported
   via Responsible Disclosure.
4. The authors accept no liability for unauthorized use.

**References:** CFAA (US), Computer Misuse Act (UK), Directive NIS2 (EU).
