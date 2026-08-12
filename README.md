<div align="center">

```
 ____            _
|  _ \ _____   _(_)_ __ ___   ___  ___
| |_) / _ \ \ / / | '_ ` _ \ / _ \/ __|
|  _ < (_) \ V /| | | | | | |  __/\__ \
|_| \_\___/ \_/ |_|_| |_| |_|\___||___/
```

# RISKX

### Enterprise Cyber-Risk CLI — Research-First. Evidence-Backed. No Guessing.

**Powered by [RAJA MUHAMMAD AWAIS](https://github.com/RajaMuhammadAwais) — Cyber Security Researcher**

[![Release](https://img.shields.io/github/v/tag/RajaMuhammadAwais/RISKX?label=release&sort=semver&color=blue)](https://github.com/RajaMuhammadAwais/RISKX/releases/tag/v0.2.0)
[![License](https://img.shields.io/badge/license-CC%20BY--NC--ND%204.0-lightgrey)](https://creativecommons.org/licenses/by-nc-nd/4.0/)
[![Go](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/RajaMuhammadAwais/RISKX)](https://goreportcard.com/report/github.com/RajaMuhammadAwais/RISKX)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-success?logo=github-actions&logoColor=white)](https://github.com/RajaMuhammadAwais/RISKX/tree/main/.github/workflows)
[![Static Analysis](https://img.shields.io/badge/staticcheck-clean-brightgreen)](https://staticcheck.dev/)
[![Tests](https://img.shields.io/badge/tests-15%2F15%20passing-green)](https://github.com/RajaMuhammadAwais/RISKX)
[![Non-Commercial](https://img.shields.io/badge/non--commercial%20open%20source-red)](NON_COMMERCIAL.md)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blueviolet)](#operating-system-compatibility)

</div>

---

## Purpose

RISKX is a command-line tool for **continuous threat-exposure management (CTEM)**. It discovers your assets passively, enriches them with verified vulnerability intelligence, scores risk with a deterministic evidence-backed model, ranks attack paths, validates findings safely, and produces executive reports and machine-readable exports — all with mandatory evidence attached to every finding.

It follows the [CISA CTEM lifecycle](https://www.cisa.gov/continuous-threat-exposure-management) — **Discover → Prioritize → Remediate → Validate** — and is grounded exclusively in verified primary sources: [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities), [FIRST](https://api.first.org/data/v1/epss), [MITRE](https://attack.mitre.org/), [OWASP](https://owasp.org/Top10/), and [OSV](https://osv.dev/).

> **THE NO-GUESSING RULE.** Facts, inferences, and recommendations are separated in the data model. Detection without evidence is reported as `insufficient` confidence — never a fabricated finding. Inferred edges and findings are explicitly labeled and never presented as confirmed. Stale feeds are marked `STALE`, never silently dropped. Feed failures raise explicit errors, never "no data".

This is a **non-commercial tool**: see [`NON_COMMERCIAL.md`](NON_COMMERCIAL.md) and the [`LICENSE`](LICENSE) (CC BY-NC-ND 4.0). You are free to use, build, and share it for research, education, and personal defense — commercial use requires a separate license from the author.

## Why RISKX

Most security tools present conclusions as facts. RISKX presents conclusions with their evidence: every finding carries *what was observed*, *which source said so*, *when it was checked*, and *how confident the tool is*. This makes the output audit-ready — an analyst can trace any line of a report back to the observation that produced it.

| Principle | How RISKX enforces it |
| --- | --- |
| No guessing | Findings without evidence get `insufficient` confidence |
| Evidence provenance | Every artifact carries source, URL, access time, version |
| Safe by default | Discovery is passive/read-only; validation needs explicit authorization |
| Freshness discipline | Feeds declare age; stale data is marked, never hidden |
| Determinism | Risk model `risk-v1` is fully deterministic and reproducible |
| Machine-readable | Canonical versioned JSON on every command (`--json`) |

## Operating System Compatibility

RISKX is written in pure Go with a pure-Go SQLite driver (no CGo), so the same binary model builds and runs on every supported platform. Compatibility was verified on **Ubuntu 24.04 (linux/amd64)**; other platforms use the identical code path.

| Operating System | Versions | Method | Status |
| --- | --- | --- | --- |
| Ubuntu | 22.04, 24.04, 25.04 | Build from source or Go install | Verified on 24.04 |
| Debian | 12 (Bookworm), 13 (Trixie) | Build from source or Go install | Supported |
| Fedora | 40, 41, 42 | Build from source or Go install | Supported |
| Arch Linux / Manjaro | Rolling | Build from source or Go install | Supported |
| openSUSE | Leap 15.6, Tumbleweed | Build from source or Go install | Supported |
| Kali Linux | Rolling, 2024/2025 | Build from source (preinstalled Go or go install) | Supported |
| CentOS Stream / AlmaLinux / Rocky | 9+ | Build from source (requires recent Go) | Supported |
| macOS | 14 (Sonoma), 15 (Sequoia), 16+ | Build from source or Go install | Supported |
| Windows | 10, 11 | Build from source or Go install (`riskx.exe`) | Supported |

## Installation

### Prerequisites (all platforms)

Go **1.25 or newer** is required. Check your version:

```bash
go version
```

**Ubuntu / Debian (latest versions):**

```bash
# Install Go 1.25+ if not present
sudo apt update
sudo apt install -y golang-go   # or download latest from https://go.dev/dl/

# Verify
go version
```

**Fedora:**

```bash
sudo dnf install -y golang
go version
```

**Arch Linux:**

```bash
sudo pacman -S go
go version
```

**macOS (Homebrew):**

```bash
brew install go
go version
```

**Windows (Scoop):**

```powershell
scoop install go
go version
```

### Method 1 — Build from source (recommended)

```bash
git clone https://github.com/RajaMuhammadAwais/RISKX.git
cd RISKX
go build -o riskx ./cmd/riskx

# Move into your PATH
sudo mv riskx /usr/local/bin/    # Linux / macOS
# or on Windows, move riskx.exe anywhere on %PATH%
```

### Method 2 — Go install

```bash
go install github.com/RajaMuhammadAwais/RISKX/cmd/riskx@v0.2.0
```

The binary lands in `$(go env GOPATH)/bin` (default `~/go/bin`).

### Method 3 — Cross-compile for another OS

```bash
GOOS=windows GOARCH=amd64 go build -o riskx.exe ./cmd/riskx
GOOS=darwin  GOARCH=arm64 go build -o riskx ./cmd/riskx
GOOS=linux   GOARCH=arm64 go build -o riskx ./cmd/riskx
```

### Quick verification

```bash
riskx version
riskx doctor          # self-diagnoses your environment
```

## Quick Start

The CTEM loop in five commands:

```bash
# 1. Discover assets (passive, read-only)
riskx discover example.com --data ./riskx.db

# 2. Enrich vulnerabilities (CISA KEV, NVD CVSS, FIRST EPSS, OSV aliases)
riskx vuln CVE-2021-44228 --data ./riskx.db

# 3. Score risk deterministically
riskx risk --data ./riskx.db

# 4. Validate safely (read-only checks, no exploitation)
riskx validate tls example.com --data ./riskx.db

# 5. Report + export for your SOC / ticketing system
riskx report summary --data ./riskx.db
riskx export sarif  --data ./riskx.db > riskx.sarif   # GitHub/SonarQube compatible
riskx export csv    --data ./riskx.db > riskx.csv
riskx export jsonl  --data ./riskx.db > riskx.jsonl
```

Run everything at once:

```bash
riskx scan example.com --mode passive
```

## Command Reference

| Command | What it does |
| --- | --- |
| `discover` | Passive asset discovery: DNS, HTTP, TLS, RDAP, TCP reachability |
| `vuln` | Vulnerability intelligence: CISA KEV, NVD CVSS, FIRST EPSS, OSV aliases |
| `risk` | Deterministic risk scoring (`risk-v1`) with factor tables |
| `attack-path` | Rank attack paths from internet entry to critical assets |
| `graph` | Inspect the evidence-backed attack graph (centrality, edges) |
| `validate` | Safe read-only validation: DNS, TLS, HTTP checks |
| `cloud` | AWS read-only cloud discovery (STS, EC2, S3, IAM) |
| `report` | Executive risk report over the evidence store |
| `export` | Export findings: JSONL, CSV, SARIF 2.1.0 |
| `assets` | List the local asset inventory |
| `scan` | Full flow: discover → enrich → risk-score |
| `policy` | Policy evaluation with CI exit codes (0/1/2) |
| `continuous` | Scheduled continuous exposure management |
| `config` | Show / validate the configuration |
| `init` | Initialize the configuration directory |
| `doctor` | Diagnose the local environment |
| `version` | Print versions (tool + all data models) |

Commands marked *future phase* (`identity`, `agent`, `mcp`) are scaffolded and reserved; they print a clear status message and do nothing silently.

## Flags Reference

### Global flags (every command)

| Flag | Short | Purpose | Default |
| --- | --- | --- | --- |
| `--help` | `-h` | Show command help | — |
| `--json` | `-j` | Emit canonical JSON output | human-readable |
| `--config` | — | Path to config file | `~/.config/riskx/config.yaml` |
| `--verbose` | `-v` | Enable debug logging | off |
| `--quiet` | `-q` | Suppress non-essential output | off |
| `--version` | — | Print version (root only) | — |

### `discover`

| Flag | Purpose | Default |
| --- | --- | --- |
| `--file` | File of targets, one per line | — |
| `--mode` | Discovery mode: `passive` or `safe` | `passive` |
| `--records` | DNS record types, comma-separated | `A,AAAA,CNAME,MX,NS,TXT` |
| `--ports` | TCP ports to probe (connect-only), comma-separated | — |
| `--data` | Evidence store path; `off` to disable; env `RISKX_DATA` | `~/.riskx/riskx.db` |

### `vuln` / `risk`

| Flag | Purpose | Default |
| --- | --- | --- |
| `--data` | Evidence store path; `off` to disable; env `RISKX_DATA` | `~/.riskx/riskx.db` |

### `validate`

| Flag | Purpose | Default |
| --- | --- | --- |
| `--kind` | Check kind: `dns`, `tls`, or `http` | `dns` |
| `--dns-type` | DNS record type for DNS checks | `A` |
| `--dns-want` | Expected DNS record values (optional) | — |
| `--mode` | Validation mode: `safe`, `validation`, or `active` | `validation` |
| `--ci` | CI mode (deterministic output) | off |
| `--preapprove` | Pre-approve the printed plan (CI only) | off |
| `--data` | Evidence store path; env `RISKX_DATA` | `~/.riskx/riskx.db` |

### `cloud discover`

| Flag | Purpose | Default |
| --- | --- | --- |
| `--action` | `whoami`, `instances`, `buckets`, `identities`, or `all` | `all` |
| `--mode` | `safe` or `validation` | `validation` |
| `--ci` | CI mode | off |
| `--preapprove` | Pre-approve the printed plan (CI only) | off |
| `--data` | Evidence store path; env `RISKX_DATA` | `~/.riskx/riskx.db` |

### `report`, `export`, `scan`, `attack-path`, `policy`, `continuous`

| Command | Notable flags |
| --- | --- |
| `report summary` | `--data` |
| `export sarif` | `--data`, `--output` (file; default stdout) |
| `export csv` / `jsonl` | `--data`, `--output` |
| `scan` | `--mode` (default `passive`), `--ci`, `--preapprove` |
| `attack-path top <n>` | `--mode` edge-status gate: `observed_only`, `evidence_backed`, `exploratory` (default `evidence_backed`) |
| `policy check` | `--file` (policy file) |
| `continuous` | `--every` cycle interval (default `24h`) |

## Examples

Passive discovery with JSON output:

```bash
riskx discover example.com --json
```

Bulk targets from a file:

```bash
riskx discover --file targets.txt --records A,MX,TXT --ports 80,443,8080
```

Validate a TLS configuration safely:

```bash
riskx validate tls example.com --json
```

Verify DNS against expected values (useful in CI):

```bash
riskx validate dns example.com --dns-want 93.184.216.34 --ci --preapprove
```

AWS cloud discovery (read-only; requires `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`):

```bash
riskx cloud discover all
riskx cloud discover --action buckets
```

Policy check for CI pipelines (exit code 0/1/2):

```bash
riskx policy check --file policy.yaml
echo $?
```

## Evidence Model

Every security artifact in RISKX carries provenance. Findings separate **FACT** (observation + evidence items), **INFERENCE** (confidence and status), and **RECOMMENDATION** (remediation, never presented as fact). Attack-graph edges carry one of four statuses:

- `observed` — directly measured in the current scan
- `inferred` — plausible from evidence, explicitly never confirmed
- `potential` — theoretically possible, no evidence yet
- `validated` — confirmed via an approved validation step

Feeds declare freshness; data older than its allowed age is marked `stale`.

## Data Sources

| Source | Use | Attribution |
| --- | --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited-vulnerability membership | CISA |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVSS vectors and scores | "Products incorporate NVD, a product of NIST. This information is not guaranteed to be accurate." |
| [FIRST EPSS](https://api.first.org/data/v1/epss) | Exploit probability scores | FIRST |
| [OSV](https://osv.dev/) | Aliases and ecosystem packages | Google / OSV |
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique classification (STIX v19.2) | MITRE |
| [CWE](https://cwe.mitre.org/) | Weakness classification | MITRE |
| [OWASP Top 10:2025](https://owasp.org/Top10/) | Application-risk classification | OWASP |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | AI-agent/MCP-risk classification | OWASP |

## Versioned Data Models

| Model | Version | Used by |
| --- | --- | --- |
| asset | asset-v1 | `discover`, `assets` |
| finding | finding-v1 | `vuln`, `report`, `export` |
| evidence | evidence-v1 | all commands |
| risk | risk-v1 | `risk` |
| graph | graph-v1 | `attack-path`, `graph` |
| storage | storage-v1 | `--data` / `RISKX_DATA` |
| report | report-v1 | `report` |

Print all versions at once with `riskx version`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | No policy violation / clean |
| 1 | Policy violation detected |
| 2 | Execution error |

## Repository Layout

```
cmd/riskx/                 CLI entry point and command tree
internal/core/             config, log, errs, mode, output, idgen, runner
internal/discovery/        dns, http, tls, rdap passive-discovery engines
internal/vulnerability/    ingest (KEV/NVD/EPSS/OSV), normalize, findings
internal/risk/             risk-v1 deterministic scoring engine
internal/graph/            graph-v1 attack graph (BFS, Dijkstra, centrality)
internal/policy/           YAML policy evaluation
internal/reporting/        report-v1 summary + SARIF 2.1.0 / CSV / JSONL export
internal/validate/         safe read-only DNS/TLS/HTTP validation
internal/cloud/            cloud-v1 AWS read-only discovery (SigV4)
internal/storage/          storage-v1 SQLite persistence
internal/evidence/         source-metadata and confidence typing
pkg/models/                canonical versioned data model
pkg/plugins/               plugin interfaces and registry
.github/workflows/         CI: test/build, lint, staticcheck, govulncheck
```

## Development

```bash
go build ./...          # compile everything
go vet ./...            # static analysis
go test ./... -short    # unit + fixture tests (live feeds skipped)
go test ./...           # includes live feed integration tests
go test ./... -race     # race detector (pure-Go SQLite driver; no gcc needed)
go test -bench=. -run=^$ ./internal/risk ./internal/vulnerability/ingest
```

## CI/CD

GitHub Actions run on every push and pull request. All action versions are pinned:

| Workflow | Checks | Pinned versions |
| --- | --- | --- |
| `ci.yml` | build (linux/darwin/windows), `go test -race`, `go vet`, `go mod tidy -diff` | actions/setup-go@v7 |
| `lint.yml` | golangci-lint (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unparam`, `unused`, `whitespace`) | golangci-lint-action@v9, linter v2.1.6 |
| `staticcheck.yml` | honnef staticcheck | dominikh/staticcheck-action@v1 |
| `vuln.yml` | govulncheck dependency scan | golang/govulncheck-action@v1 |

## Benchmarks

Measured on live hardware (Ubuntu 24.04, linux/amd64, Go 1.26.5) — see [`docs/research/benchmarks.md`](docs/research/benchmarks.md):

| Benchmark | Result |
| --- | --- |
| Risk scoring (`risk-v1`, 7 factors) | ~2.2 µs/op, 21 allocs |
| CISA KEV ingestion (1,666 verified rows) | ~1.8–2.0 ms, schema-validated |
| Test suite | 15/15 packages pass with race detector; vet + staticcheck clean |

## License

RISKX is **non-commercial open-source software** authored by [Raja Muhammad Awais](https://github.com/RajaMuhammadAwais).

- Code, documentation, and research artifacts: **[CC BY-NC-ND 4.0](LICENSE)** — free to use, build, and share for non-commercial purposes with attribution; no commercial use and no derivative works without permission.
- Commercial licensing: contact the author (see [`NON_COMMERCIAL.md`](NON_COMMERCIAL.md)).
- Third-party data: CISA, NIST NVD, FIRST EPSS, MITRE, OWASP, and OSV data carry their own licenses and attribution requirements, which RISKX reproduces verbatim in its outputs.

## Author

> **RAJA MUHAMMAD AWAIS** — Cyber Security Researcher
> Built with a research-first methodology: every capability grounded in verified primary sources, every output evidence-backed.

[![GitHub](https://img.shields.io/badge/GitHub-RajaMuhammadAwais-181717?logo=github&logoColor=white)](https://github.com/RajaMuhammadAwais)

---

*If this project helps you, star it on GitHub — and remember: scan only what you own or are authorized to test.*
