# RISKX

RISKX is an enterprise cyber-risk command-line tool built **research-first**: every capability is grounded in verified primary sources (CISA, NIST, MITRE, OWASP, FIRST, OSV), and every output is evidence-backed. Nothing is guessed — detection without evidence is reported as `insufficient` confidence, never as a fabricated finding.

The design follows the [CISA Continuous Threat Exposure Management (CTEM)](https://www.cisa.gov/continuous-threat-exposure-management) lifecycle — **Discover → Prioritize → Remediate → Validate** — and implements a deterministic-risk model (`risk-v1`) with an evidence-and-confidence data model (`evidence-v1`, `finding-v1`, `asset-v1`).

> **NO GUESSING RULE.** Facts, inferences, and recommendations are separated in the data model. Inferred edges and findings are explicitly labeled and never presented as confirmed. Stale feeds are marked `STALE`, never silently dropped. Feed failures raise explicit errors, never "no data".

## Features

| Capability | Command | Evidence basis |
|---|---|---|
| Passive asset discovery (DNS, HTTP, TLS, RDAP, port reachability) | `riskx discover` | Observed network/certificate/registration data with per-asset provenance |
| Vulnerability intelligence (CISA KEV, NVD CVSS, FIRST EPSS, OSV aliases) | `riskx vuln` | Verified feed schemas (11-column KEV, NVD API 2.0, EPSS) with source citations |
| Deterministic risk scoring (`risk-v1`) | `riskx risk` | Evidence-tagged factors: exposure, known exploitation, vulnerability, privilege, criticality |
| Attack-path analysis (`graph-v1`) | `riskx attack-path top`, `riskx graph` | BFS enumeration + weighted Dijkstra ranking + centrality; edge statuses Observed/Inferred/Potential/Validated gate reports |
| Policy evaluation with CLI exit codes (0/1/2) | `riskx policy check`, `riskx doctor` | YAML policy; built-in default policy |
| Security operating modes | `riskx scan` (passive/reporting/enforced) | Mode authorizer: no action runs without explicit approval; plan printed first |
| Executive risk report over the evidence store | `riskx report summary` | Stored assets/findings/scores; missing sections listed as deferred, never fabricated |
| Findings export (JSONL, CSV, SARIF 2.1.0) | `riskx export jsonl\|csv\|sarif --data` | SARIF validated against the official OASIS Standard + Errata 01 schema |
| Safe read-only validation (DNS, TLS, HTTP) | `riskx validate` | Real network observations; failures are recorded as evidence, never silent |
| AWS cloud discovery (read-only STS/EC2/S3/IAM) | `riskx cloud discover` | SigV4-signed query APIs, cross-verified against the AWS SDK signer |
| Evidence store persistence (SQLite, 0600) | `--data` / `RISKX_DATA` on all commands | storage-v1 schema; content-addressed, idempotent writes |

## Quick start

Build from source (requires Go 1.25+):

```bash
go build -o riskx ./cmd/riskx
```

Discover an asset passively:

```bash
./riskx discover example.com
./riskx discover example.com --json
```

Look up a CVE across all intelligence sources:

```bash
./riskx vuln CVE-2021-44228 --json
```

Rank attack paths from internet-exposed entry points to critical assets:

```bash
./riskx attack-path top 5 --mode evidence_backed
./riskx graph centrality
```

Persist findings to the local evidence store and produce an executive report:

```bash
./riskx discover example.com --data ./riskx.db
./riskx vuln CVE-2021-44228 --data ./riskx.db
./riskx risk --data ./riskx.db
./riskx report summary --data ./riskx.db
./riskx export sarif --data ./riskx.db > riskx.sarif
```

Validate a target safely (read-only checks, no active exploitation):

```bash
./riskx validate dns example.com
./riskx validate tls example.com
./riskx validate http https://example.com
```

Discover AWS assets with read-only IAM credentials (SigV4, query APIs only):

```bash
./riskx cloud discover all   # requires AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
```

## Evidence model

RISKX's core contract is that every security artifact carries provenance. Findings separate **FACT** (observation + evidence items), **INFERENCE** (confidence and status), and **RECOMMENDATION** (remediation, never presented as fact). The attack graph includes only evidence-backed edges, and each edge carries a status:

- `observed` — directly measured in the current scan
- `inferred` — plausible from evidence, explicitly never confirmed
- `potential` — theoretically possible, no evidence yet
- `validated` — confirmed via an approved validation step

Feeds declare freshness; data older than its allowed age is marked `stale`. CISA blocks some networks; the verified KEV snapshot embedded in the binary is used as a fallback and is explicitly reported as stale in that case.

## Data sources

| Source | Use | Attribution |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited-vulnerability membership | CISA |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVSS vectors and scores | "Products incorporate NVD, a product of NIST. This information is not guaranteed to be accurate." |
| [FIRST EPSS](https://api.first.org/data/v1/epss) | Exploit probability scores | FIRST |
| [OSV](https://osv.dev/) | Aliases and ecosystem packages | Google / OSV |
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique classification (STIX v19.2) | MITRE |
| [CWE](https://cwe.mitre.org/) | Weakness classification | MITRE |
| [OWASP Top 10:2025](https://owasp.org/Top10/) | Application-risk classification | OWASP |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | AI-agent/MCP-risk classification | OWASP |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No policy violation / clean |
| 1 | Policy violation detected |
| 2 | Execution error |

## Repository layout

```
cmd/riskx/                 CLI entry point and command tree (cobra)
internal/core/             config, log, errs, mode, output, idgen, runner
internal/discovery/        dns, http, tls, rdap passive-discovery engines
internal/vulnerability/    ingest (KEV/NVD/EPSS/OSV), normalize, findings
internal/risk/             risk-v1 deterministic scoring engine
internal/graph/            graph-v1 attack graph (BFS, Dijkstra, centrality)
internal/policy/           YAML policy evaluation
internal/storage/          storage-v1 (SQLite) persistence
internal/evidence/         source-metadata and confidence typing
pkg/models/                canonical versioned data model
pkg/plugins/               plugin interfaces and registry
docs/research/             13 research documents with source tiers
docs/architecture/         architecture-v1
docs/adr/                  9 architecture decision records (ADR-0008 storage wiring, ADR-0009 CI pinning)
.github/workflows/     CI/CD: test, lint, staticcheck, govulncheck
tests/fixtures/            verified feed snapshots (KEV 2026-08-12)
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

GitHub Actions run on every push and pull request (see `.github/workflows/`). Action versions are pinned and were verified against the upstream repositories on 2026-08-12:

| Workflow | Checks | Pinned action versions |
|---|---|---|
| `ci.yml` | build + `go test -race` (linux/darwin/windows), `go vet`, `go mod tidy -diff` | actions/setup-go@v7 |
| `lint.yml` | golangci-lint v2.1.6 (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unparam`, `unused`, `whitespace`) | golangci/golangci-lint-action@v9 |
| `staticcheck.yml` | honnef staticcheck over the whole module | dominikh/staticcheck-action@v1 |
| `vuln.yml` | `govulncheck` dependency vulnerability scan | golang/govulncheck-action@v1 |

Measured performance and the quality-gate matrix are recorded in [`docs/research/benchmarks.md`](docs/research/benchmarks.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
