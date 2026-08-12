# RISKX Research Directory

This directory contains the Phase 0 research deliverables required by the RISKX specification (§1 and §50). Every document follows the evidence format **Claim → Evidence → Source → Source type → Publication/update date → Confidence → Implementation impact**, using the Tier 1 (authoritative) / Tier 2 (primary technical research) / Tier 3 (high-quality secondary) evidence hierarchy.

## Documents

| Document | Focus |
| --- | --- |
| [research-index.md](./research-index.md) | Master index: source register, verified live APIs, tracked unverified claims |
| [ctem.md](./ctem.md) | CTEM lifecycle, EASM/CAASM/ASM landscape, CISA prioritization guidance |
| [vulnerability-intelligence.md](./vulnerability-intelligence.md) | NVD, KEV, EPSS, OSV, CWE, ATT&CK, CVSS/CPE; schemas, limits, licensing |
| [attack-path-analysis.md](./attack-path-analysis.md) | Attack graph theory, algorithms, hazard modeling, edge evidence statuses |
| [risk-model.md](./risk-model.md) | Risk scoring approaches, explainability, FP/FN management |
| [standards.md](./standards.md) | NIST AI RMF/600-1/800-1, COSAiS, OWASP Top 10:2025, CIS Controls v8.1 |
| [ai-agent-security.md](./ai-agent-security.md) | AI-agent identity/authz/audit research; detection feasibility; gaps |
| [mcp-security.md](./mcp-security.md) | MCP protocol model, confused deputy, OWASP MCP Top 10 v0.1 |
| [cloud-security.md](./cloud-security.md) | Shared responsibility, SCuBA, provider evaluation for Phase 7 |
| [competitive-analysis.md](./competitive-analysis.md) | Market structure, commercial leaders, evidenced gaps, OSS foundations |
| [technology-evaluation.md](./technology-evaluation.md) | Language/CLI/DB/graph/plugin/output/supply-chain evaluations |
| [threat-model.md](./threat-model.md) | Threat model of RISKX itself (STRIDE over nine data flows) |

## Working Files

`_notes.md` is the accumulating verified-claims log from live research (kept as evidence of what was tested). `_spec_map.md` is the internal mapping of specification sections to deliverables. Both are internal working files, not user-facing documentation.

## Verification Record

All external sources were accessed on **2026-08-12**. Live API tests are recorded in research-index.md. Claims that could not be verified are marked `UNVERIFIED` in the documents that use them and listed in the "Verified Live APIs" and tracking sections of the index — they are never silently assumed true, per the No-Guessing rule (§0 of the specification).
