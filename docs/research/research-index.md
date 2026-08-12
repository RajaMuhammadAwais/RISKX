# RISKX Research Index

**Status:** Phase 0 — Research deliverable
**Access date for all sources:** 2026-08-12 (unless otherwise noted)
**Maintainer:** Manus AI
**Confidence convention:** HIGH = claim verified against the cited primary source by live test or direct inspection; MEDIUM = claim from a reputable secondary source that quotes or summarizes the primary source; LOW = third-party claim requiring further verification.

## Document Register

| Document | Purpose | Status |
| --- | --- | --- |
| [ctem.md](./ctem.md) | CTEM lifecycle, exposure management landscape, CISA cross-cuts | Complete |
| [vulnerability-intelligence.md](./vulnerability-intelligence.md) | NVD, KEV, EPSS, OSV, CVSS, CWE, CPE, vendor advisories, exploit telemetry | Complete |
| [attack-path-analysis.md](./attack-path-analysis.md) | Attack graph theory, algorithms, hazard modeling, path scoring | Complete |
| [risk-model.md](./risk-model.md) | Risk scoring approaches, evidence model, FP/FN management | Complete |
| [standards.md](./standards.md) | NIST, ISO, CIS, OWASP baseline standards and their current versions | Complete |
| [ai-agent-security.md](./ai-agent-security.md) | NIST/COSAIS/CAISI, OWASP Agentic AI, agent identity and privilege research | Complete |
| [mcp-security.md](./mcp-security.md) | MCP protocol model, OWASP MCP Top 10 v0.1, trust boundaries | Complete |
| [cloud-security.md](./cloud-security.md) | Shared responsibility, SCuBA, CSPM/CAASM provider evaluation | Complete |
| [competitive-analysis.md](./competitive-analysis.md) | Commercial and open-source landscape, gaps, differentiation | Complete |
| [technology-evaluation.md](./technology-evaluation.md) | Language, database, graph, plugin, and tooling evaluation | Complete |
| [threat-model.md](./threat-model.md) | Threat model of RISKX itself (data flows, STRIDE, mitigations) | Complete |
| [README.md](./README.md) | Overview and reading guide for this directory | Complete |

## Evidence Tier Assignments

Tier 1 (authoritative) sources verified in this research wave include the CISA KEV catalog (live CSV schema verified), NVD API 2.0 documentation and live endpoint, FIRST EPSS API (live query verified), OSV API (live query verified), MITRE ATT&CK STIX data repository (release verified), MITRE CWE API (live query verified, one endpoint unverified and marked), the OWASP MCP Top 10 project page, the official MCP specification site, CISA SCuBA and nation-state actor pages, the CISA CTEM page, AWS and Azure shared responsibility documentation, and official NIST publication paths (AI 100-1, AI 600-1, AI 800-1 ipd2, SP 800-218A, COSAiS project page).

Tier 2 (primary technical research) sources include the ACM CCS AISec 2021 EPSS paper, the arXiv Bayesian local-exploit-hazard paper (2607.24618), probabilistic attack graph literature (Homer et al.), and OWASP Top 10:2025 methodology documentation.

Tier 3 (high-quality secondary) sources are used only where Tier 1/2 are unavailable, and are explicitly flagged inside the documents that rely on them.

## Verified Live APIs (test results, 2026-08-12)

| Source | Endpoint tested | Result | Notes |
| --- | --- | --- | --- |
| CISA KEV | cisa.gov CSV | Live, 11 columns, ~1666 rows | Schema verified (see vulnerability-intelligence.md) |
| NVD API 2.0 | services.nvd.nist.gov REST | Live | Pagination startIndex/resultsPerPage; optional apikey header |
| EPSS | api.first.org/data/v1/epss | Live, no auth | CVE-2021-44228 → epss 0.999990000, percentile 1.0 |
| OSV | api.osv.dev/v1/vulns/{id} | Live | OSV schema verified |
| MITRE ATT&CK | GitHub STIX release zip | Live | Latest release = v19.2 (2026-04-28) |
| CWE API | cwe-api.mitre.org | Partially live | Single-CWE JSON works; the top-25 path returned an error and is marked UNVERIFIED |
| NVD bulk JSON feeds | nvd.nist.gov feed URLs | **403 via curl** | NVD now directs users to API 2.0 |

## Claims Requiring Further Verification (tracked)

The following are explicitly not treated as facts. They appear in the research documents with UNVERIFIED tags and an implementation impact of "defer until verified": the CWE top-25 API path, the NIST AI-111 publication family (all candidate URLs returned 404 at access time; NIST AI 100-1, 600-1, and 800-1 are used instead), exact NVD API 2.0 rate-limit values (the developers page must be checked after obtaining an API key before production ingestion), and the full MCP architecture page at modelcontextprotocol.io (extraction failed twice; the security best practices page and the spec repository are used instead).

## How to Read the Evidence

Every substantive claim in a research document carries the structure required by the specification: Claim, Evidence, Source, Source type, Publication/update date, Confidence, Implementation impact. Where multiple sources support a claim, the lowest-confidence source determines the claim's confidence ceiling.
