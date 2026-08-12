# RISKX Architecture v1

**Status:** Phase 0 deliverable
**Date:** 2026-08-12
**Based on:** docs/research/* (Phase 0 research), RISKX specification §§0-52

## 1. Design Principles

The architecture implements five binding specification requirements. Determinism first: every detection, score, and finding is produced by deterministic logic operating on verified evidence; an optional AI layer (Phase 10) never overwrites verified facts (§20). Evidence everywhere: no finding, risk score, or graph edge exists without attached evidence with source, timestamp, and confidence (§19, §44). Safe by default: PASSIVE mode with no destructive behavior; active validation requires explicit authorization and a pre-execution plan (§8). Explainable risk: every score reports its factors, weights, evidence, and model version (§12). Failure safety: unavailable feeds are marked stale, denied permissions mark visibility incomplete, uncertain fingerprints never claim exact versions (§48).

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLI (cmd/riskx)                           │
│  init | version | config | doctor | discover | assets | scan    │
│  vuln | cloud | identity | ai | agent | mcp | graph | risk      │
│  report | export | policy | validate | continuous                │
│  flags: --help --version --output --config --quiet --verbose     │
│         --json --mode --ci                                        │
└───────────────┬──────────────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────────────┐
│  internal/core      runner · modes · evidence store · IDs        │
├──────────────────────────────────────────────────────────────────┤
│  internal/asset     asset model · inventory · normalization       │
│  internal/discovery domain · DNS · HTTP · TLS · network plugins  │
│  internal/vulnerability  KEV · NVD · EPSS · OSV · CWE ingestion  │
│  internal/risk      risk-v1 scoring · factors · weights          │
│  internal/graph     graph model · traversal · centrality         │
│  internal/evidence  evidence model · sources · confidence        │
│  internal/policy    policy files · exit codes · suppressions     │
│  internal/reporting human · JSON · JSONL · CSV serializers       │
│  internal/storage   SQLite repository (local CLI)                │
├──────────────────────────────────────────────────────────────────┤
│  pkg/models         canonical Go types (asset-v1, finding-v1)    │
│  pkg/plugins        plugin interfaces + registry (plugin-v1)     │
├──────────────────────────────────────────────────────────────────┤
│  adapters/          format adapters (SARIF future, JSONL)         │
│  plugins/           built-in plugin implementations               │
└──────────────────────────────────────────────────────────────────┘
```

Data flows follow the CTEM lifecycle: Discover (`riskx discover` populates the asset inventory with provenance), Prioritize (`riskx scan`/`riskx vuln` ingest intelligence; `riskx risk` scores; `riskx graph` builds paths), Validate (`riskx validate --mode validation` with explicit authorization), Mobilize (`riskx report`/`export`/`policy`/`continuous`).

## 3. Canonical Data Model (asset-v1 / finding-v1 / evidence-v1)

Core entities: `Asset` (supertype with kinds host, ip, domain, service, application, api, cloud_resource, container, k8s_resource, repository, ai_endpoint, mcp_endpoint, agent, mcp_server, identity), `Host`, `IP`, `Domain`, `Service`, `Vulnerability`, `Finding`, `AttackPath`, `Risk`, `Evidence`, `Policy`, `Remediation`, `Identity`, `Agent`, `MCPServer`, `MCPTool`, `Relationship` (exposes/runs/affected_by/accessible_by/connected_to/participates_in), `Suppression`. All entities carry stable, content-addressed IDs; relationships carry an evidence status: **Observed, Inferred, Potential, Validated**. Findings carry: finding_id (RISKX-...), asset, observation, evidence[], severity, confidence, validation_status, suppression, classification (CWE, OWASP Top 10:2025, OWASP MCP Top 10, ATT&CK technique ID with spec version).

## 4. Risk Model (risk-v1)

The risk score is a weighted product-sum over seven named factors, each sourced from verified evidence:

| Factor | Evidence source | Weight (default) |
| --- | --- | --- |
| Exposure (E) | Discovery provenance (internet-facing, internal) | 0.20 |
| Known exploitation (K) | CISA KEV membership (fused with telemetry caveat) | 0.20 |
| Predicted exploitation (P) | EPSS score (stale if >7 days old) | 0.15 |
| Asset criticality (C) | Asset classification + user policy | 0.15 |
| Attack-path position (A) | Graph reachability/centrality | 0.10 |
| Identity privilege (I) | IAM evidence (Phase 6+) | 0.10 |
| Standards gap (S) | CIS IG1/CPG/OWASP mapping | 0.10 |

`risk = 100 × Σ(w_i × f_i)`, factors normalized to [0,1]. Every output prints the factor table, weights, evidence citations, and `Model Version: risk-v1`. Weights are configurable YAML and covered by golden tests. The model explicitly documents its limits: it is a prioritization aid, not a breach prediction; KEV absence is never scored as safety (vulnerability-intelligence.md §9).

## 5. Attack Graph (graph-v1)

Nodes are assets/identities; edges are capability/exploitability relationships with evidence status and per-edge risk weight. MVP traversal: BFS enumeration + Dijkstra-style weighted ranking to enumerate paths Internet→entry→privilege→target, with centrality metrics (degree, betweenness approximation). Edge weights derive from risk-v1 factors on the underlying vulnerability/identity evidence. Inferred edges are visually and textually distinguished from observed/validated ones; reports never present inferred paths as confirmed attacks.

## 6. Plugin System (plugin-v1)

Plugins implement interfaces in pkg/plugins (DiscoveryPlugin, AssetPlugin, VulnerabilityPlugin, CloudPlugin, IdentityPlugin, AgentPlugin, MCPPlugin, RiskPlugin, ReporterPlugin, ExporterPlugin). Each plugin declares version, capabilities, configuration schema, permissions, and logging/error hooks. MVP ships built-in plugins registered in-process; the registry is designed so out-of-process plugin execution (ADR-0006) can be added without breaking interfaces.

## 7. Storage (storage-v1)

SQLite (embedded, pure-Go driver preferred per technology-evaluation.md §3) holds inventory, findings, evidence, and policy state. Feeds are cached with fetch timestamps and staleness flags. Graph state is held in-memory within a scan session for MVP (bounded scope); persistence of graph state is a tracked future item. Failure modes are first-class: feed unavailability writes a stale marker rather than silent gaps.

## 8. Security Operating Modes

| Mode | Behavior | Default methods |
| --- | --- | --- |
| PASSIVE | Read-only observation; no probes beyond what public infrastructure returns | DNS/WHOIS/CT logs, public APIs, HTTP GET of own-configured endpoints |
| SAFE | Passive + authenticated read (user-provided credentials used read-only) | Cloud API reads, repo file reads |
| ACTIVE | Explicitly authorized intrusive checks (banner reads, safe probes) | Requires --mode active + confirmation of listed actions |
| VALIDATION | Validates specific findings against user-authorized validation steps | Pre-execution plan printed first; never exploits |

## 9. CLI Contract

Exit codes (§33): 0 = no policy violation, 1 = policy violation found, 2 = execution error. All findings emit stable JSON under `--json`; human output is a rendering layer over the same structures. `--ci` sets machine-friendly output and deterministic exit behavior. Telemetry: none in MVP (off by default forever unless explicitly configured per §46).

## 10. Versioning

| Component | Version |
| --- | --- |
| RISKX | 0.1.0 |
| Risk model | risk-v1 |
| Asset schema | asset-v1 |
| Finding schema | finding-v1 |
| Evidence schema | evidence-v1 |
| Plugin API | plugin-v1 |
| Protocol assumptions | MCP 2025-06-18/draft, ATT&CK v19.2 |

## 11. Known Limitations and Research Gaps

Known limitations: MVP scope covers domains/DNS/HTTP/TLS/basic network discovery (Phase 2) and vulnerability intelligence over KEV/NVD/EPSS/OSV/CWE (Phase 3); containers, K8s, CI/CD, cloud providers, and identity engines are later phases. Research gaps carried forward: CWE top-25 API path (UNVERIFIED), NIST AI-111 family (404 at access date — using AI 100-1/600-1/800-1 instead), NVD API rate-limit values post-key (verify before production ingestion), full MCP architecture page (extraction failed twice — retry at implementation), exact SARIF version (Phase 11), agent-risk benchmark evidence (Phase 8). Local-hazard Bayesian aggregation (arXiv 2607.24618) requires telemetry the MVP lacks and is deferred to a future risk model revision.

## 12. MVP Scope

**In scope (Phases 0-5):** Go CLI scaffold with required flags; config/logging/errors/output; plugin interfaces; asset discovery (domains, DNS, HTTP, TLS, basic network); asset inventory; vulnerability intelligence (KEV, NVD, EPSS, OSV, CWE lookup); risk-v1 scoring with evidence; attack graph with path ranking; policy engine (YAML, exit codes); human/JSON/JSONL/CSV output; unit/integration/security tests with fixtures; documentation and ADRs.

**Out of scope (explicitly deferred):** cloud provider checks (Phase 7), identity engines (Phase 6), AI-agent/MCP engines (Phases 8-9), AI/RAG layer (Phase 10), SARIF and enterprise CI/RBAC/signed releases (Phase 11), SaaS posture (SCuBA-style), container/K8s deep inspection, BAS/active exploitation, multi-tenant server deployment.
