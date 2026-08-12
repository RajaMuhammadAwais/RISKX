# Risk Model Research

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. What Existing Approaches Measure

**Claim:** CVSS measures inherent severity, not organizational risk. EPSS predicts the probability an average organization's vulnerability will be exploited in the next 30 days. KEV records observed exploitation. None of these alone answers "what should be fixed first."
**Evidence:** FIRST EPSS model paper (Jacobs et al., ACM CCS Workshop AISec 2021, dl.acm.org/doi/abs/10.1145/3436242) shows EPSS derived via BIC-optimal Bayesian models over CVSS features; CISA positions KEV as a prioritization input, not a risk score.
**Source:** dl.acm.org/doi/abs/10.1145/3436242 (Tier 2); cisa.gov (Tier 1)
**Confidence:** HIGH
**Implementation impact:** The RISKX risk model composes these inputs as separate, named factors. CVSS and EPSS numbers are imported, never recalculated from memory (spec §12).

## 2. Attack-Path and Local-Hazard Approaches

**Claim:** Academic work converts global exploit probabilities into organization-local hazard rates: a Bayesian framework models control effectiveness as a Beta distribution, updates it with Beta-Binomial inference from telemetry, applies Weibull-shaped decay calibrated from KEV timing, and aggregates per-vulnerability hazards to host/network/org levels under an independence assumption.
**Evidence:** Shaffer & Voicu, "Modeling Local Exploit Hazard" (arXiv:2607.24618, 2026-07). Probabilistic attack-graph risk analysis is established in the Homer et al. line of work (Springer, "Security risk analysis of enterprise networks using probabilistic attack graphs").
**Source:** arxiv.org/abs/2607.24618 (Tier 2); Springer (Tier 2)
**Confidence:** HIGH for the model's existence and claims; MEDIUM for its transferability to RISKX's MVP (local telemetry may not exist yet)
**Implementation impact:** The RISKX risk-v1 model borrows two transferable ideas: (a) exploit likelihood decays with vulnerability age (KEV-timing-shaped decay), (b) per-asset control-effectiveness observations belong in the evidence model for future Beta updating. Full Bayesian updating is out of MVP scope pending telemetry data (research gap).

## 3. Composite CTEM Prioritization

**Claim:** CTEM's Prioritize stage combines exploitability evidence, asset exposure, business criticality, and threat intelligence rather than any single number.
**Evidence:** CISA CTEM documentation (Tier 1); standard exposure-management practice reflected in vendor architectures (Bitsight, JupiterOne — Tier 3).
**Confidence:** HIGH (Tier 1 framing)
**Implementation impact:** risk-v1 factors (see architecture-v1.md) map one-to-one onto evidence sources: exposure (discovery provenance), known exploitation (KEV), predicted exploitation (EPSS), criticality (asset classification), attack-path position (graph centrality/reachability), identity privilege (Phase 6), and standards alignment (CIS IG1/CPGs).

## 4. Explainability and Determinism Requirements

**Claim:** Every risk score must report why, evidence, factors, weights, and model version; the model must be explainable, deterministic, configurable, versioned, testable, and auditable; an AI-generated score must never be presented as objective truth.
**Evidence:** Spec §12 (binding project requirement).
**Implementation impact:** risk-v1 outputs a factor table with named weights and citations (`source` metadata per spec §44). Weights are configurable YAML, versioned under `risk-v1`, and covered by golden tests with fixtures. Optional AI assists explanation only, downstream of the deterministic score (spec §20).

## 5. False-Positive and False-Negative Management

**Claim:** Every detector should track finding, confidence, evidence, validation status, false-positive status, suppression reason, and expiration; suppression must never be permanent or silent.
**Evidence:** Spec §30 (binding requirement); this reflects industry practice in finding-management workflows.
**Implementation impact:** Findings carry `validation_status` and `suppression` (reason, owner, created_at, expires_at) fields. Suppressions are explicit CLI commands (`--suppress`, `--exception`) with expiration.

## 6. Failure Behavior of Risk Inputs

**Claim:** When a vulnerability feed is unavailable, RISKX must not pretend data is current; it must mark the feed stale. When visibility is incomplete, the model must not assume absence of findings.
**Evidence:** Spec §48 (binding requirement).
**Implementation impact:** The risk engine records per-input staleness flags in its output metadata. A risk computation over incomplete data is labeled accordingly rather than silently degraded.

## 7. Score Calibration and Claims Discipline

**Claim:** No detection-rate or accuracy claims may be made without measured benchmark evidence; methodology and hardware must be recorded.
**Evidence:** Spec §29, §49 (binding requirements).
**Implementation impact:** A benchmark harness records discovery speed, memory, CPU, and graph traversal performance with methodology notes. The risk model documents its factors and weights but claims no accuracy percentage.
