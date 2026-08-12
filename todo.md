# RISKX Master TODO

**Date:** 2026-08-12
**Basis:** RISKX specification §§0-52, Phase 0 research deliverables, architecture-v1.md, ADR-0001..0007.
**Method:** Each item carries a status, and progress is tracked in `docs/research/_progress.md`. Implementation follows the spec's loop (RESEARCH → ... → IMPLEMENT → TEST → DOCUMENT → VERIFY) and the Definition of Done (§43) per feature.

## Phase 0 — Research (complete)

- [x] docs/research/README.md
- [x] docs/research/research-index.md
- [x] docs/research/ctem.md
- [x] docs/research/vulnerability-intelligence.md
- [x] docs/research/attack-path-analysis.md
- [x] docs/research/risk-model.md
- [x] docs/research/standards.md
- [x] docs/research/ai-agent-security.md
- [x] docs/research/mcp-security.md
- [x] docs/research/cloud-security.md
- [x] docs/research/competitive-analysis.md
- [x] docs/research/technology-evaluation.md
- [x] docs/research/threat-model.md
- [x] docs/architecture/architecture-v1.md
- [x] docs/adr/ADR-0001..0007
- [x] MVP scope / non-MVP scope / tech decisions / security assumptions / known limitations / research gaps (in architecture-v1.md and research docs)
- [x] Repository initialized (private), Go module, LICENSE, SECURITY.md

## Phase 1 — Core CLI

- [x] 1.1 `go get` pinned dependencies: spf13/cobra (+pflag), pure-Go SQLite driver (modernc.org/sqlite preferred per ADR-0003)
- [x] 1.2 `pkg/models`: canonical types with versions asset-v1 / finding-v1 / evidence-v1 (Asset supertype + kinds; Host/IP/Domain/Service/Vulnerability/Finding/AttackPath/Risk/Evidence/Policy/Remediation/Identity/Agent/MCPServer/MCPTool/Relationship with status Observed|Inferred|Potential|Validated; Suppression)
- [x] 1.3 `internal/evidence`: evidence model + source metadata (organization/document/url/accessed/version per §44); confidence typing
- [x] 1.4 `internal/core/config`: YAML config loading, 0600 writes, path-traversal protection
- [x] 1.5 `internal/core/log`: structured logger with secret redaction; secure error types (`internal/core/errs`)
- [x] 1.6 `internal/core/mode`: security modes PASSIVE|SAFE|ACTIVE|VALIDATION with gating helpers and explicit-authorization flow for VALIDATION
- [x] 1.7 `internal/core/output`: output engine — human table + `--json`; JSON metadata with model versions + NVD attribution when applicable
- [x] 1.8 `internal/core/idgen`: stable content-addressed IDs (finding RISKX-..., asset, evidence)
- [x] 1.9 `pkg/plugins`: plugin interfaces (Discovery/Asset/Vulnerability/Cloud/Identity/Agent/MCP/Risk/Reporter/ExporterPlugin) + registry + capability/permission model per ADR-0006
- [x] 1.10 `internal/policy`: policy engine — YAML policy files (thresholds, KEV fail, internet-exposed-admin fail), policy evaluation returning structured result; `--ci` exit codes 0/1/2 documented
- [x] 1.11 `cmd/riskx`: root + global flags (--help/--version/--output/--config/--quiet/--verbose/--json/--ci) and command scaffolds for init/version/config/doctor/discover/assets/scan/vuln/cloud/identity/ai/agent/mcp/graph/attack-path/risk/report/export/policy/validate/continuous
- [x] 1.12 `internal/core/runner`: command runner tying mode + policy + output + exit codes
- [x] 1.13 Phase 1 tests: unit (models, config, policy, modes), negative cases (malformed config, invalid targets), fixtures, race detector pass
- [x] 1.14 Code quality: gofmt/go vet/staticcheck/golangci-lint clean; no ignored errors; no banned patterns per §24

## Phase 2 — Asset Discovery

- [x] 2.1 DNS discovery: system resolver + record types (A/AAAA/CNAME/MX/NS/TXT), PTR/rDNS, dedup, provenance JSON per asset
- [x] 2.2 HTTP discovery: HEAD/GET with timeouts, banner capture, status/headers fingerprinting, robots detection of tech hints
- [x] 2.3 TLS discovery: certificate parsing (SANs, issuer, validity, chain), weak-config hints (expired/self-signed/short-key)
- [x] 2.4 RDAP/WHOIS (RDAP only — data.rdap.org verified source; classic WHOIS deferred), domain registration evidence
- [x] 2.5 Basic network discovery: TCP connect probe with timeouts on configured port lists (connect-only, no SYN crafting)
- [x] 2.6 Asset normalization + inventory: supertype classification, stable IDs, dedup, SQLite persistence (storage-v1, 0600 DB file)
- [x] 2.7 `riskx discover` command wiring (single target, list of targets, file input with validation)
- [x] 2.8 Phase 2 tests: unit + integration with fixtures (recorded DNS/TLS/HTTP responses), network-failure cases, duplicate-asset cases, malformed-input cases; golden tests for asset JSON

## Phase 3 — Vulnerability Intelligence

- [x] 3.1 KEV ingestion: CSV parse with schema validation, live fetch + caching + staleness flags, `tests/fixtures/kev.csv` regression fixture
- [x] 3.2 NVD API 2.0 client: pagination, rate-limit respect, required attribution string in outputs, error/stale handling (403 → explicit error, not silence)
- [x] 3.3 EPSS client: api.first.org with stale-marking (>7 days)
- [x] 3.4 OSV client: api.osv.dev with alias/related handling for dedup
- [x] 3.5 CWE lookup: single-CWE endpoint only (top-25 UNVERIFIED — skipped with comment), OWASP Top 10:2025 mapping table for classification
- [x] 3.6 `internal/vulnerability/normalize`: normalized Vulnerability model fusing KEV/NVD/EPSS/OSV/CWE with provenance per source
- [x] 3.7 `riskx vuln` command: lookup + bulk enrichment of discovered assets (CPE matching deferred — documented limitation)
- [x] 3.8 Phase 3 tests: unit with fixtures (KEV snapshot, recorded NVD/EPSS/OSV responses), API-failure and rate-limit simulation cases, malformed-CVE-input cases, duplicate-vuln cases

## Phase 4 — Risk Engine (risk-v1)

- [x] 4.1 Factor implementations: exposure, known-exploitation (KEV), predicted-exploitation (EPSS), criticality, path-position hook, identity-privilege hook, standards-gap hook
- [x] 4.2 Scoring function with configurable YAML weights; factor table output; `Model Version: risk-v1`
- [x] 4.3 Evidence fusion: finding ← asset + vuln + evidence chain; confidence typing high/medium/low/insufficient
- [x] 4.4 Staleness + incomplete-visibility metadata per §48 (feed stale / visibility incomplete surfaced in outputs)
- [x] 4.5 Golden tests: fixed fixtures assert exact scores + factor tables; negative tests (missing evidence → capped scores, never guessed)
- [x] 4.6 `riskx risk` command + policy integration (risk-v1 scores feed policy evaluation)

## Phase 5 — Attack Graph (graph-v1)

- [x] 5.1 Graph data model: nodes (assets/identities), edges with status + risk weight + evidence
- [x] 5.2 Traversals: BFS enumeration, Dijkstra weighted ranking, degree + approximate betweenness centrality
- [x] 5.3 Path rendering: Internet→entry→privilege→target chains with per-edge evidence status; Inferred clearly distinguished
- [x] 5.4 `riskx graph` and `riskx attack-path` commands
- [x] 5.5 Tests: unit graph fixtures, path-ranking golden tests, duplicate-edge handling
- [x] 5.6 Benchmark harness: graph traversal perf with methodology notes (spec §29) — results recorded in docs/research/benchmarks.md

## Phase 6 — Reporting & Export (v0.2)

- [x] 6.1 `riskx report summary`: executive summary over the evidence store — assets, findings, risk scores, critical exposures, affected assets, evidence citations, recommendations; missing sections (attack-path/identity/cloud/agent/MCP) listed as deferred, never fabricated
- [x] 6.2 JSONL and CSV serializers over canonical findings (findings + evidence provenance); `riskx export jsonl|csv|sarif --data`
- [x] 6.3 SARIF evaluation + exporter (SARIF 2.1.0 re-verified against OASIS Standard + Errata 01, 2026-08-12; exporter implemented with schema validation in tests)
- [ ] 6.4 `--suppress` / `--exception` with reason/owner/created_at/expires_at (no permanent silent suppression)
- [x] 6.5 Phase 6 tests: CSV/JSONL/SARIF roundtrip and golden tests, SARIF schema validation against OASIS 2.1.0 + Errata 01

## Cross-cutting (parallel, ongoing)

- [x] Q.1 README.md final (evidence-based, no marketing claims, attribution strings, versions table, CLI contract, limitations)
- [x] Q.2 CI workflows: ci.yml (build + test -race, linux/darwin/windows), lint.yml (golangci-lint v2.1.6), staticcheck.yml, vuln.yml (govulncheck) — all action versions pinned and verified 2026-08-12
- [x] Q.3 Dependency scan baseline (go mod tidy + audit); secret-scan baseline of repo (audit run locally; govulncheck job added in CI)
- [x] Q.4 Benchmarks: risk scoring (2170 ns/op) and KEV ingestion (1.97 ms/1666 rows) recorded with hardware/methodology in docs/research/benchmarks.md
- [ ] Q.5 Re-verify tracked UNVERIFIED items before each dependent implementation (SARIF version re-verified 2026-08-12; CWE top-25, NVD auth rate limits remain)

## Verification Gates (Definition of Done, per spec §43)

Before any phase is marked done: research cited, primary sources identified, architecture/ADR updated if changed, threat model reviewed, implementation complete, unit + integration + security + negative tests added, documentation + CLI help added, error handling + evidence model + logging implemented, performance considered, false-positive risk evaluated, limitations documented, reproducible tests present, code quality checks pass.

## Out of MVP Scope (tracked, not to be built yet)

Phase 6 (Identity/IAM), Phase 8 (AI-Agent), Phase 9 (MCP), Phase 10 (AI/RAG), Phase 11 (Enterprise: RBAC, audit, SBOM, signed releases, centralized deployment, schema migrations), CAASM aggregation, CPE-based component matching, SaaS posture (SCuBA), containers/K8s deep inspection, BAS/active exploitation, multi-tenant server mode, PostgreSQL backend, graph-store migration, cloud config audit (CIS AWS Foundations). v0.2 scope (Phase 7 start): AWS readonly discovery via env creds (STS/EC2/S3/IAM query APIs), reporting-v1, SARIF 2.1.0 export, storage persistence wiring, real validate checks.

## v0.2.0 release items

- [x] `riskx validate` (DNS/TLS/HTTP safe read-only checks, evidence-recorded outcomes)
- [x] `internal/cloud/aws`: SigV4 signer (cross-verified vs botocore), STS/EC2/S3/IAM read-only discovery, `riskx cloud discover`
- [x] storage-v1 wired into discover/vuln/risk/validate/cloud/report/export (reserved-keyword and time-scan bugs fixed with regression tests)
- [x] ADR-0008 (storage wiring) and ADR-0009 (CI pinning)
- [x] README.md updated for v0.2.0 (commands, quick-start, CI/CD table, benchmarks pointer)
