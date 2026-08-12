# Spec Section Map (from /home/ubuntu/upload/pasted_content.txt)

Sections and what they require (for Phase 0 doc generation):
- 0: NO GUESSING rule (mark UNVERIFIED, need evidence for security claims)
- 1: docs/research/ must contain: research-index.md, architecture-research.md,
  threat-model.md, standards.md, ai-agent-security.md, mcp-security.md,
  cloud-security.md, vulnerability-intelligence.md, attack-path-analysis.md,
  risk-model.md, competitive-analysis.md, technology-evaluation.md.
  Each doc must contain: Claim / Evidence / Source / Source type /
  Publication date / Confidence / Implementation impact. Tier 1/2/3 evidence hierarchy.
- 2: research baseline: CTEM, ASM/EASM/CAASM, VM, BAS, attack-path mgmt; CVE/CVSS/CWE/CPE/EPSS/KEV/OSV/GHSAs/vendor advisories/exploit availability/ransomware.
  Five-way distinction: exists ≠ exposed ≠ exploitable ≠ actively exploited ≠ material business risk.
- 3: AI-agent security first-class: identity/authZ/delegation/least-priv/excessive agency/
  tool perms/agent-to-agent/prompt injection/tool poisoning/memory/insecure workflows/
  impersonation/non-repudiation/auditability/sandboxing/human approval/runtime policy/
  agent supply chain. Use current NIST material as primary evidence.
- 4: MCP security from official sources: architecture, transports, auth, tools, resources,
  prompts, trust boundaries, server/client identity, remote vs local servers, malicious
  tools, tool poisoning, confused deputy, credential exposure, escalation, supply chain,
  runtime enforcement. Version protocol assumptions.
- 5: objective pipeline: Asset Discovery → Inventory → Vuln Intel → Identity & Permission
  → Cloud → AI-Agent → MCP → Attack Graph → Exposure → Risk Prioritization →
  Remediation → Continuous Verification. Focus: what can be compromised, how, what next,
  what first.
- 6: Language evaluation: Go recommended (networking, concurrency, portable binary,
  low ops overhead, cross-platform, CLI tooling) — evaluate Go vs Rust vs Python and
  document it (do not accept assumption undocumented).
- 7: CLI commands (incremental per roadmap): init, version, config, doctor, discover,
  assets, scan, vuln, cloud, identity, ai scan, agent scan, mcp scan, graph,
  attack-path, risk, report, export, policy, validate, continuous. Every command needs
  --help, --version, --output, --config, --quiet, --verbose, --json where appropriate.
  Machine-readable stable output for CI/SIEM/SOAR/scripts/dashboards.
- 8: Security operating modes: PASSIVE / SAFE / ACTIVE / VALIDATION. Default PASSIVE.
  Never silently destructive/intrusive. Active validation needs explicit user
  authorization + pre-execution explanation. No uncontrolled exploitation.
- 9: Discovery engine: domains, subdomains, DNS, IPs, TLS certs, HTTP services, ports,
  network services, APIs, cloud assets, containers, K8s, repos, CI/CD, AI endpoints,
  MCP endpoints. Separate discovery/identification/fingerprinting/risk assessment.
  No service/version claim without evidence. Provenance JSON: asset/source/method/
  timestamp/confidence.
- 10: Asset data model: Asset, Host, IP, Domain, Service, Application, API,
  CloudResource, Container, K8sResource, Repository, Identity, CredentialReference,
  Agent, MCPServer, MCPTool, Vulnerability, Finding, AttackPath, Risk, Evidence,
  Policy, Remediation. Stable IDs, relationships, example tree.
- 11: Vuln engine: no vuln DB from memory; integrate NVD/KEV/OSV/GHSA/vendor/EPSS/CVSS/
  CWE/CPE. Document API limits, licensing, update frequency, reliability, schema, auth,
  caching, failure modes. Normalized model: CVE, CWE, CVSS, EPSS, KEV, affected
  products/versions, references, evidence, timestamps.
- 12: Risk engine: no random formula; research CVSS/EPSS/KEV/CTEM/attack-path/
  criticality/impact/identity/exposure/exploitability/threat intel; transparent,
  explainable, deterministic, configurable, versioned, testable, auditable. Every score
  must show why/evidence/factors/weights/model version (risk-v1 example with 6 factors).
  Never present AI-generated score as objective truth.
- 13: Attack graph: Internet→Asset→Vuln→InitialAccess→Identity→Privilege→Resource→
  SensitiveData. Distinguish Observed/Inferred/Potential/Validated (never label inferred
  as confirmed). Path ranking; evaluate BFS/DFS/Dijkstra/weighted shortest path/
  multi-factor scoring/centrality/priv-esc paths; document algorithm choice.
- 14: Identity risk: IAM/RBAC/ABAC/least priv/escalation/service identities/cloud roles/
  API keys/OAuth/workload/machine/AI-agent identity. Identity→Permission→Resource.
  Detect: excessive priv, wildcards, unused, chains, public identities, long-lived creds,
  high-impact service accounts, agent identities w/ excessive authority. Never claim
  danger without permission/resource relationship.
- 15: AI agent engine: detect LangGraph/CrewAI/AutoGen/OpenAI Agents/Anthropic/custom/
  RAG/tool-using/multi-agent. Detection needs method/evidence/confidence. Agent model:
  model, tools, permissions, memory, data sources, external APIs, identity, exec env,
  human approval boundary.
- 16: Agent risk model: evaluate identity/authz/tool access/data access/execution/
  network/secrets/memory/external comms/human approval/autonomy/auditability/isolation.
  Capability graph (READ DB, WRITE GitHub, EXECUTE shell, ACCESS AWS, SEND email);
  check capabilities vs intended role. Not excessive agency from tool existence alone.
- 17: MCP engine: riskx mcp scan. Inspect only safe/legal observation. Analyze server,
  client, tools, resources, prompts, auth, authz, metadata, network location,
  dependencies, secrets, capabilities, trust relationships. Map to OWASP MCP risks.
  Finding = Finding/Evidence/Severity/Confidence/Relevant standard/Remediation.
- 18: Cloud security phased: evaluate AWS/Azure/GCP (API availability, OSS ecosystem,
  security relevance, docs, feasibility, demand); pick one. Then IAM, network exposure,
  (continues in file)
- 19-52: (read earlier) identity/cloud/AI-agent/MCP engines, attack graph, exposure
  analysis, remediation, continuous verification, plugin architecture, testing/lint/
  CI gates, benchmarks, security (supply chain, SBOM, SLSA, license compliance),
  documentation standards, phased roadmap, FIRST TASK = complete Phase 0 research
  deliverables: docs/research/*, architecture v1, ADRs, MVP scope definition, roadmap.

## Sections 19-52 (verified reading)

- 19: Evidence system mandatory: finding_id RISKX-..., asset, observation, evidence[]
  {type, source, timestamp, value}, confidence high. Must answer "Why risky?"
- 20: AI/RAG layer NOT in critical detection path by default. Deterministic first:
  Data → Normalized Findings → Evidence → Risk Engine → Optional AI. AI never overwrites
  facts. Separate FACT / INFERENCE / RECOMMENDATION.
- 21: RAG with evidence grounding; sources NIST/CISA/MITRE/OWASP/vendor; preserve
  references; never fabricate citations; INSUFFICIENT EVIDENCE fallback.
- 22: Plugin interfaces: Discovery/Asset/Vulnerability/Cloud/Identity/Agent/MCP/
  Risk/Reporter/ExporterPlugin. Plugins have version, capabilities, config, permissions,
  logging, errors, tests. Clean interfaces, no tight coupling.
- 23: Database evaluation SQLite vs PostgreSQL vs Neo4j/embedded graph. Hypothesis:
  SQLite→local CLI, PostgreSQL→server, graph store→attack paths. Benchmark first.
- 24: Code quality: SOLID/DRY/KISS/Clean Arch/secure-by-design/least-priv/fail-secure/
  explicit errors. Tooling: go modules, golangci-lint, gofmt, go vet, staticcheck,
  unit/integration/fuzz, race detector, dep scanning, SAST. Banned: ignored errors,
  hardcoded secrets, insecure defaults, unnecessary privs, arbitrary shell exec,
  unsafe cmd construction, blind deserialization, unvalidated input.
- 25: Self-security threat model targets: CLI, config, credentials, plugins, network,
  downloaded vuln data, AI providers, RAG docs, cache, DB, reports, logs, updates.
  Implement credential isolation, file perms, TLS verify, input validation, dep pinning,
  signature verify, safe temp files, secure logging, secret redaction, path traversal +
  cmd injection protection, plugin isolation.
- 26: Supply chain: SBOM, dep pinning, dep scanning, reproducible builds, signed
  releases, checksums, GH Actions security, secret scanning, container scanning,
  provenance. Evaluate SLSA/Sigstore/Cosign/in-toto/CycloneDX/SPDX — verify specs.
- 27: tests/ with unit/integration/security/fixtures/regression/fuzz/performance/e2e.
  Test positive/negative/FP/FN/malformed/network failure/API failure/rate limits/
  permission failures/partial discovery/stale data/duplicates. Reproducible fixture per finding.
- 28: Security test lab: isolated env, intentional vuln systems only, Docker/K8s/
  local cloud emulators, mock APIs/IAM, test MCP servers/agents. Never test without authorization.
- 29: Benchmarking: no claims unless measured. Benchmark discovery speed, memory, CPU,
  DB, graph traversal, vuln ingestion, large inventories, parallel scans, FP/FN.
  Record methodology + hardware.
- 30: False-positive research: track finding/confidence/evidence/validation status/
  FP status/suppression reason/expiration. No permanent silent suppression.
  --suppress/--exception with reason/owner/created_at/expires_at.
- 31: Output: CLI human, JSON, JSONL, CSV, SARIF (verify current SARIF spec first).
- 32: Reporting: riskx report with Executive Summary/Risk Overview/Critical Exposures/
  Attack Paths/Affected Assets/Identity/Cloud/AI-Agent/MCP Risks/Evidence/Remediation/
  Trends. Separate executive/technical/machine-readable.
- 33: CI/CD: GitHub Actions/GitLab/Jenkins/generic. riskx scan --ci. Exit codes:
  0 no policy violation, 1 policy violation, 2 execution error.
- 34: Policy engine: YAML policy (critical_risk threshold 90 fail; kev fail;
  internet_exposed_admin fail). Not hardcoded in detectors.
- 35: Remediation: evidence-based per finding: problem/why/evidence/fix/verification/
  rollback. No auto modification in early versions; later needs explicit authorization,
  dry-run, preview, approval, rollback, audit log.
- 36: Roadmap Phases 0-11: 0 Research (research/, threat model, ADRs, competitive,
  tech eval); 1 Core CLI (Go CLI, config, logging, errors, output, plugin interfaces);
  2 Asset Discovery (domains, DNS, HTTP, TLS, basic network, inventory); 3 Vuln Intel
  (CVE/KEV/CVSS/EPSS/CWE/OSV); 4 Risk Engine (evidence, criticality, exposure,
  exploitability, threat intel, scoring); 5 Attack Graph (asset/identity relationships,
  paths, scoring); 6 Identity (IAM, privs, service accounts, permissions); 7 Cloud
  (researched provider); 8 AI-Agent (discovery, capabilities, identity, permissions, risk);
  9 MCP (discovery, tool analysis, authz, findings); 10 AI/RAG (only after deterministic stable);
  11 Enterprise (CI/CD, SARIF, RBAC, policy, audit, SBOM, signed releases, centralized).
- 37: Repo structure: cmd/riskx, internal/{asset,discovery,vulnerability,identity,cloud,
  agent,mcp,graph,risk,evidence,policy,reporting,storage}, pkg/{models,plugins,interfaces},
  adapters/, plugins/, tests/, fixtures/, docs/{research,architecture,threat-model,adr},
  configs/, scripts/, .github/, Dockerfile, go.mod, Makefile, LICENSE, README.md, SECURITY.md.
  Adjust after research, don't blindly follow.
- 38: ADRs in docs/adr/ADR-XXXX-name.md: context/problem/options/evidence/decision/
  trade-offs/security implications/migration path. Decisions: language, CLI framework,
  DB, graph engine, plugin system, vuln sources, cloud arch, AI arch, RAG, risk
  algorithm, MCP implementation, auth, storage.
- 39: Competitive research products: Tenable, Qualys, Rapid7, Wiz, MS Defender,
  CrowdStrike, Palo Alto, Orca, Snyk, Semgrep, GitLab, AI-SPM, CNAPP, CTEM, MCP
  security, AI-agent security vendors. Identify exists/works/doesn't/expensive/
  missing/emerging/differentiation.
- 40: Differentiation thesis to TEST not assume: CTEM + Attack Graph + Identity Risk +
  AI-Agent Security + MCP Security. Change strategy if research shows better combo.
- 41: Research quality gate: 14 questions (problem real? who? existing tools? standards?
  sources? data? FP/FN risks? security impact? testable? reproducible? safe? limitations?).
  If unanswerable: DO NOT IMPLEMENT YET.
- 42: Implementation loop: RESEARCH→EVIDENCE→DESIGN→THREAT MODEL→ADR→IMPLEMENT→
  UNIT TEST→INTEGRATION→SECURITY TEST→BENCHMARK→DOCUMENT→VERIFY.
- 43: Definition of done (18 checkboxes incl. evidence model, CLI help, reproducible
  tests, code quality gates).
- 44: Source citation inside project: source {organization, document, url, accessed,
  version}. Never fabricate URLs; never cite unconsulted sources.
- 45: Versioning: RISKX 0.1.0, Risk Model risk-v1, Schema asset-v1, Plugin API plugin-v1.
- 46: Telemetry OFF by default, documented, configurable, minimal, auditable.
- 47: AI provider abstraction: LLMProvider/EmbeddingProvider/RerankerProvider
  interfaces; local models where practical; AI optional.
- 48: Failure behavior: vuln feed down → mark stale; permission denied → mark visibility
  incomplete; uncertain fingerprint → no exact version claim; AI fails → deterministic
  results continue.
- 49: No marketing claims without evidence.
- 50: FIRST TASK = STEP 1: produce docs/research/{README.md, research-index.md,
  competitive-analysis.md, technology-evaluation.md, ai-agent-security.md,
  mcp-security.md, ctem.md, vulnerability-intelligence.md, attack-path-analysis.md,
  risk-model.md, threat-model.md}, then docs/architecture/architecture-v1.md + docs/adr/,
  then MVP scope/non-MVP, architecture, tech decisions, security assumptions, known
  limitations, research gaps, implementation roadmap. Only then implementation.
- 51: Continuous research loop on each feature (check current docs/standards/APIs/libs/
  vulns/compatibility).
