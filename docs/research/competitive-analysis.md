# Competitive Analysis

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. Market Structure

**Claim:** The exposure-management market splits into EASM (internet-facing discovery/monitoring), CAASM (internal asset-data aggregation), CNAPP (cloud-native protection), VM (vulnerability management), AI-SPM (AI-security posture), and newer AI-agent/MCP security products. CTEM is the lifecycle that spans them.
**Evidence:** Gartner category definitions (Tier 3 quoting Tier 1 analyst material); vendor positioning pages (Tier 2/3).
**Confidence:** MEDIUM for category boundaries (analyst material); HIGH for the existence of each product class
**Implementation impact:** RISKX's MVP implements the Discover/Prioritize core that belongs to EASM+VM, with CAASM/CNAPP/AI-SPM as later plugin phases.

## 2. Commercial Leaders and Constraints

**Claim:** Leading commercial platforms in 2026 include Bitsight (EASM+CTI+TPRM), Rapid7 (VM with external visibility), Mandiant Attack Surface Management (Google TI), JupiterOne (CAASM graph), CrowdStrike Falcon Surface, Wiz (CNAPP), Tenable, Qualys, Orca, Snyk, Semgrep, GitLab security, plus emerging AI-SPM and MCP/AI-agent security vendors.
**Evidence:** Bitsight 2026 EASM guide (Tier 3 vendor research citing Forrester TEI and KuppingerCole); vendor sites and documentation.
**Source type:** Tier 3 (market guides); Tier 2 (vendor documentation)
**Confidence:** MEDIUM
**Implementation impact:** RISKX cannot replicate proprietary telemetry (internet-wide scan data, CTI feeds). It competes on openness, evidence provenance, and cost of entry, not on proprietary data.

## 3. Verified Gaps RISKX Can Target

**Claim:** Four gaps are evidenced: (a) commercial products offer no self-serve/CLI-first tier — Bitsight pricing is custom-only; (b) commercial risk scores are opaque, with no per-finding evidence trail; (c) AI-agent and MCP surface classes are emerging and underserved; (d) KEV-only or CVSS-only prioritization ignores exploit-window telemetry showing KEV lags real exploitation by 2-4 weeks.
**Evidence:** Bitsight pricing page ("custom pricing only"); risk-model.md telemetry evidence; mcp-security.md taxonomy evidence; ai-agent-security.md standards-gap evidence.
**Source type:** Tier 2/3
**Confidence:** MEDIUM
**Implementation impact:** These gaps directly motivate the spec's binding requirements: evidence model (§19), explainable risk (§12), MCP/agent engines (§15-17), and CLI-first design (§7).

## 4. Open-Source Reference Points (Not Competitors, Foundations)

**Claim:** The open-source ecosystem provides reference implementations per capability: subfinder/Amass (subdomain discovery, MIT), crt.sh (certificate transparency), massdns (bulk DNS), nmap/zmap/masscan (port scanning, GPL-2.0), Project Sonar and scans.io (internet survey data), CloudScraper/GCPBucketBrute (cloud storage exposure), ScubaGear/ScubaGoggles (SaaS config baselines, cisagov), Prowler (AWS posture, Apache-2.0), ScubaGear (Microsoft 365), redhuntlabs/Awesome-Asset-Discovery (curated catalog, CC0).
**Evidence:** GitHub repositories and official project pages verified at access date; licenses as stated on each repository.
**Source type:** Tier 1 (official repositories)
**Confidence:** HIGH
**Implementation impact:** RISKX implements its own network/DNS logic in the MVP (no GPL dependency contamination in the core; MIT-licensed components may be used as documented dependencies with attribution). License compliance is an ADR (ADR-0004).

## 5. Differentiation Thesis

**Claim:** The testable thesis is CTEM lifecycle + attack graph + identity risk + AI-agent security + MCP security in one evidence-first open CLI. Research did not surface a better combination, but the thesis remains flagged for re-testing per spec §40 when Phase 8/9 findings mature.
**Evidence:** Synthesis of sections 3-4 of this document.
**Confidence:** MEDIUM (strategic inference from Tier 2/3 sources)
**Implementation impact:** MVP validates the thesis at its smallest surface: asset discovery + vulnerability intelligence + evidence-based risk. Agent and MCP engines extend it in Phases 8-9.
