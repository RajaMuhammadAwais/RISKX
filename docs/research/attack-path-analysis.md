# Attack Path Analysis Research

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. What an Attack Path Is, Formally

**Claim:** An attack path is a sequence of edges from an initial entry point (e.g., Internet) through assets, vulnerabilities, identities, and privileges to a target asset (e.g., sensitive data). Probabilistic attack-graph research models nodes as system states and edges as exploitation/privilege steps with associated probabilities.
**Evidence:** Homer et al., "Security risk analysis of enterprise networks using probabilistic attack graphs" (Springer) and the follow-on book "Quantitative security risk assessment of enterprise networks" (Springer) establish enumeration-based attack graphs with system-risk metrics.
**Source:** Springer (Tier 2)
**Confidence:** HIGH for the model class; the RISKX instantiation is a simplified, evidence-tagged variant (see decision)
**Implementation impact:** The graph schema carries per-edge evidence and a `status` of Observed / Inferred / Potential / Validated. Inferred paths are never presented as confirmed attacks (spec §13).

## 2. Algorithm Candidates

**Claim:** Candidate path-analysis algorithms include BFS/DFS enumeration, Dijkstra/weighted shortest path, multi-factor path scoring, graph centrality measures, and privilege-escalation-path detection.
**Evidence:** Standard graph-algorithm literature; enterprise attack-path products (JupiterOne, Bitsight, CyberTotal) implement graph-based path ranking; the arXiv local-hazard paper aggregates hazards additively under independence.
**Source:** academic literature (Tier 2); vendor documentation (Tier 3)
**Confidence:** HIGH that these classes exist; the best choice depends on RISKX's graph size and is documented in ADR-0005
**Implementation impact:** MVP implements deterministic enumeration with per-edge risk weights (a Dijkstra-like ranked traversal) plus centrality metrics. Full probabilistic inference (Bayesian networks over the graph) is deferred — it requires telemetry data the MVP does not have (research gap).

## 3. Evidence Status on Edges

**Claim:** Attack graphs must distinguish Observed (directly measured, e.g., asset scan showed the service), Inferred (plausible from evidence but not directly measured), Potential (theoretically possible), and Validated (confirmed via safe validation mode).
**Evidence:** Spec §13 (binding requirement); this matches the discovery/identification/fingerprinting separation in §9.
**Implementation impact:** Graph edges and node relationships carry `status`. Reports render each status distinctly; aggregation logic weights statuses differently (Observed/Validated > Inferred > Potential).

## 4. Local Hazard Aggregation

**Claim:** Under independence, per-vulnerability daily hazard rates aggregate by summation up to host, network, and organization levels, and candidate remediation actions can be ranked by projected hazard reduction under fixed capacity.
**Evidence:** Shaffer & Voicu (arXiv:2607.24618, Tier 2).
**Confidence:** HIGH for the source's claim; applicability to RISKX depends on having per-asset control data (not yet in MVP)
**Implementation impact:** Path scoring in risk-v1 uses hazard-inspired weights on edges (EPSS × exposure × criticality) rather than full survival analysis. The additive-aggregation property motivates the later Phase 4b scoring iteration once telemetry exists.

## 5. Limitations and Known Risks of Graph-Based Prioritization

**Claim:** Attack graphs suffer from state-space explosion for large networks; probabilistic models can hide assumptions; and inferred paths can be misread as confirmed attack routes by consumers of reports.
**Evidence:** Homer et al. discuss complexity management; spec §13, §41 require explicit limitation documentation and reproducibility.
**Confidence:** HIGH
**Implementation impact:** Graph construction is bounded (MVP: single-scan scope); the report renderer prints the evidence status of every path; a documented "graph scope" section of the report explains what is inside/outside the analyzed surface.
