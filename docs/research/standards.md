# Standards Baseline

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. NIST AI Risk Management Framework

**Claim:** NIST AI 100-1 "Artificial Intelligence Risk Management Framework (AI RMF 1.0)" is the current baseline AI risk vocabulary; NIST AI 600-1 "Generative AI Profile" is final (2024-07-26); NIST AI 800-1 2pd "Managing Misuse Risk for Dual-Use Foundation Models" (ipd2, 2025-01) covers misuse pathways.
**Evidence:** nist.gov/itl/ai-risk-management-framework (Tier 1); nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf and NIST.AI.800-1.ipd2.pdf both reachable on 2026-08-12.
**Confidence:** HIGH
**Implementation impact:** AI-agent risk findings cite AI RMF functions (GOVERN, MAP, MEASURE, MANAGE) and AI 600-1 profile categories. The RISKX AI-agent risk taxonomy maps to these.

## 2. NIST Agent Security Status

**Claim:** As of 2026-08-12, NIST's agent-specific SP 800-53 control overlays (COSAIS use cases 3-4: single and multi-agent systems) are NOT yet published; the Predictive-AI annotated outline (discussion draft) was published 2026-01-08. Referencing final agent overlays would be fabrication.
**Evidence:** csrc.nist.gov/projects/cosais (created 2025-07-10, updated 2026-01-08) lists the five use cases; no final agent-overlay publication exists on the project page.
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** RISKX agent-risk findings cite COSAiS as "in progress / draft" only. No compliance claims against agent overlays. The CAISI AI Agent Standards Initiative (launched 2026-02-17) and NCCoE concept paper (2026-02-05) are tracked as emerging; they inform the identity/authorization/auditability factors, not formal compliance.

## 3. NIST Empirical Agent Security Research

**Claim:** NIST's empirical research (January 2025, with the UK AI Safety Institute, using the AgentDojo framework) found agent-hijacking attacks succeeded at 81% against a 11% baseline, roughly 7x improvement with optimized prompts.
**Evidence:** CSA research note on the NIST AI Agent Standards Initiative (Tier 3 secondary); the underlying repository github.com/usnistgov/agentdojo-inspect exists (Tier 1 repository).
**Confidence:** MEDIUM (headline figures from a Tier 3 source; the repo is Tier 1 but I did not re-run the study)
**Implementation impact:** Agent-hijacking (indirect prompt injection) is treated as a high-severity finding class with MEDIUM confidence ceiling until the primary paper is independently verified. Findings cite the AgentDojo repo.

## 4. OWASP Top 10:2025

**Claim:** OWASP Top 10:2025 categories are A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions; 248 CWEs mapped across 10 categories; A03 is new and carries the highest average CVE exploit/impact scores.
**Evidence:** owasp.org/Top10/2025/0x00_2025-Introduction/ and the A01-A10 pages (Tier 1, released November 2025).
**Confidence:** HIGH
**Implementation impact:** RISKX finding taxonomy includes an `owasp_top10_2025` classification field for applicable findings (particularly A01, A02, A03, A08, A09).

## 5. CIS Controls v8.1

**Claim:** CIS Critical Security Controls v8.1 organizes controls into Implementation Groups IG1 (essential cyber hygiene), IG2, and IG3.
**Evidence:** cisecurity.org/controls/v8 and IG1 page (Tier 1).
**Confidence:** HIGH
**Implementation impact:** Policy files can reference CIS controls by ID; the default policy aligns with IG1 hygiene controls as a baseline.

## 6. ISO/IEC

**Claim:** ISO/IEC 27001/27005 remain the standard ISMS/risk-assessment references but their full texts are behind purchase walls; NIST/OWASP/CISA materials are the practical primary sources for an open-source tool.
**Evidence:** csrc.nist.gov CSF 2.0 crosswalks to ISO; official ISO pages require purchase for full normative text.
**Confidence:** HIGH (availability status), MEDIUM (content details)
**Implementation impact:** RISKX references ISO by identifier only; normative content comes from freely accessible NIST/OWASP/CISA sources.

## 7. CVSS/CVE/CPE Standards

**Claim:** CVSS 3.1 is the current dominant scoring standard (4.0 published but not yet dominant in NVD metrics); CVE numbering is operated by CNAs; CPE 2.3 is the NVD product dictionary format.
**Evidence:** first.org/cvss (Tier 1); nvd.nist.gov (Tier 1); NVD API 2.0 metrics observed to carry cvssMetricV31.
**Confidence:** HIGH
**Implementation impact:** See vulnerability-intelligence.md §7.

## 8. Standards Not Yet Applicable (tracked, not fabricated)

**Claim:** No final federal agentic-AI security standard exists as of 2026-08-12; the MITRE ATT&CK/ATLAS frameworks do not yet cover multi-agent lateral movement or reasoning-layer attacks as dedicated techniques.
**Evidence:** NCCoE concept paper (2026-02-05) describes the gap explicitly; ATT&CK v19.2 release notes cover AI/social-engineering technique additions but no multi-agent category.
**Confidence:** MEDIUM (gap claims from Tier 2/3 synthesis; no counter-evidence found at primary sources)
**Implementation impact:** RISKX defines its own agent-risk taxonomy mapped to NIST AI RMF + OWASP Agentic AI categories, with the gap documented rather than concealed.
