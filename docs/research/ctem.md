# CTEM and the Exposure Management Landscape

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. What CTEM Is

**Claim:** CISA defines Continuous Threat Exposure Management (CTEM) as a five-stage programmatic approach: Scope, Discover, Prioritize, Validate, and Mobilize.
**Evidence:** The CISA CTEM overview page describes the five stages and positions CTEM as a continuous, programmatic way to manage exposure.
**Source:** cisa.gov/topics/continuous-threat-exposure-management
**Source type:** Tier 1 — U.S. government primary source
**Publication date:** Updated periodically; accessed 2026-08-12
**Confidence:** HIGH
**Implementation impact:** RISKX command taxonomy maps directly onto CTEM stages: `discover`/`assets` → Discover, `scan`/`vuln` → Prioritize inputs, `validate` → Validate, `risk`/`attack-path` → Prioritize, `report`/`export` → Mobilize. The CLI should expose these stages explicitly rather than inventing a novel lifecycle.

## 2. The Five-Stage Lifecycle

**Claim:** CTEM stages are Scope (defining what to protect), Discover (finding assets and exposures), Prioritize (ranking what matters most), Validate (confirming exploitability safely), and Mobilize (driving remediation action across teams).
**Evidence:** CISA CTEM page and CISA Secure-Our-World CTEM guidance both describe these stages and their sequencing.
**Source:** cisa.gov/topics/continuous-threat-exposure-management; cisa.gov/secure-our-world
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** The `--mode` flag semantics (PASSIVE, SAFE, ACTIVE, VALIDATION) implement the Validate stage safely: default PASSIVE covers Discover and Prioritize inputs; explicit VALIDATION mode covers the Validate stage with pre-execution explanation.

## 3. EASM, CAASM, and ASM

**Claim:** Gartner established EASM as a market category focused on continuous discovery, inventory, and monitoring of internet-facing assets. CAASM aggregates internal asset data from CMDB, ITSM, cloud, and endpoint sources. ASM is the umbrella.
**Evidence:** Gartner market guide and EASM definition pages; Bitsight 2026 EASM platform guide; Omdia 2026 market commentary.
**Source:** gartner.com/en/documents/5482995; bitsight.com/guides/best-external-attack-surface-management-platforms-for-global-enterprises; omnia.tech.informa.com
**Source type:** Tier 2/3 (market analysts); vendor documentation used for product capabilities
**Confidence:** MEDIUM for market definitions (Tier 3 quoting Gartner), HIGH for the EASM capability list from the Bitsight guide
**Implementation impact:** RISKX positions itself as a CLI-first EASM/CTEM engine with CAASM-style aggregation as a future phase. MVP covers the Discover/Prioritize core; CAASM aggregation is out of MVP scope (research gap acknowledged).

## 4. Attack-Path Management and BAS

**Claim:** Attack-path management and breach-and-attack simulation are complementary disciplines; attack-path management reasons about reachable critical assets through the exposure graph, while BAS actively tests controls.
**Evidence:** Vendor and analyst literature (JupiterOne, Bitsight, Qualys commentary) consistently distinguish these categories. CISA validation guidance (top common vulnerabilities and misconfigurations advisories) covers the Validate stage without requiring active exploitation.
**Source:** jupiterone.com/blog/better-together-cybersecurity-asset-management-and-external-attack-surface-management; cisa.gov
**Source type:** Tier 3
**Confidence:** MEDIUM
**Implementation impact:** RISKX attack graph (Phase 5) is analytical (path scoring), never active exploitation, per spec §8. BAS-style active validation is explicitly a future mode requiring explicit authorization, consistent with CTEM Validate.

## 5. CISA Operational Guidance Relevant to Prioritization

**Claim:** CISA recommends using the KEV catalog as an input to vulnerability-management prioritization, tracks Cybersecurity Performance Goals (CPGs) as a minimal baseline, and publishes joint advisories on the top common vulnerabilities and the top 10 misconfigurations.
**Evidence:** CISA nation-state threat page and CTEM guidance both reference KEV for prioritization, CPGs, and the joint advisory AA23-278A (top 10 misconfigurations).
**Source:** cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** KEV must be a first-class input to the risk engine (§4 of the roadmap). CPGs and the misconfiguration advisory become candidate built-in policy files under `configs/`.

## 6. Differentiation Implication

**Claim:** The strongest defensible differentiation for RISKX combines the CTEM lifecycle (discover/prioritize/validate) with an evidence-based attack graph and first-class AI-agent/MCP surface classes, delivered as an open, CLI-first tool.
**Evidence:** Competitive analysis (competitive-analysis.md) shows commercial CTEM/EASM products are GUI/SaaS-first with custom enterprise pricing and opaque scoring; no open-source CLI tool integrates KEV/EPSS/attack-graph reasoning with MCP and agent exposure as an explicit surface class.
**Source:** competitive-analysis.md (this repository)
**Source type:** Derived from Tier 1/2/3 sources
**Confidence:** MEDIUM
**Implementation impact:** This thesis is testable against the competitive analysis and retained for now, flagged to be revisited per spec §40 if new evidence emerges.
