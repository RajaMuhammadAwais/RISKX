# ADR-0005: Graph Algorithms — Weighted Traversal + Centrality (MVP)

**Status:** Accepted
**Date:** 2026-08-08-12
**Note:** Date: 2026-08-12

## Context

The attack graph is a core RISKX component (§13). The specification requires evaluation of BFS, DFS, Dijkstra, weighted shortest path, multi-factor path scoring, graph centrality, and privilege-escalation-path detection, and requires documentation of why chosen algorithms are appropriate.

## Problem

Choose graph algorithms for MVP-scale attack-path analysis.

## Options Considered

1. **Full probabilistic attack-graph inference** (Bayesian networks over enumerated paths, per Homer et al.) — most rigorous. Trade-off: requires probability estimates per edge that MVP evidence cannot yet supply; computational complexity grows exponentially with graph depth; research gap acknowledged in attack-path-analysis.md.
2. **Pure BFS/DFS enumeration** — simple, complete enumeration. Trade-off: no ranking; reports would list all paths without priority, failing the "what should be fixed first" product focus (§5).
3. **Dijkstra-style weighted traversal + centrality** — ranks paths by cumulative evidence-derived edge weights; centrality (degree, betweenness approximation) identifies pivot assets. Trade-off: weights are a simplification of true exploitation probability; independence assumptions documented in risk-model.md §2.

## Evidence

Algorithm suitability research in attack-path-analysis.md; hazard-aggregation literature (arXiv 2607.24618) informs future probabilistic upgrades; state-space caution limits MVP graph scope.

## Decision

MVP uses: (a) BFS enumeration from entry nodes to enumerate paths, (b) Dijkstra-style traversal with per-edge risk weights (derived from risk-v1 factors on the underlying evidence) to rank paths, and (c) degree + approximate betweenness centrality to surface pivot assets. Edge statuses (Observed/Inferred/Potential/Validated) gate which edges participate in each report mode.

## Trade-offs

Accepted: deterministic weighting instead of full probabilistic inference; approximate betweenness instead of exact (acceptable at MVP scale; exact algorithm documented as upgrade). Mitigated: every weight is traceable to evidence; the model version (graph-v1) makes future algorithm swaps auditable.

## Security Implications

Graph construction only includes evidence-backed nodes/edges; inferred edges never render as confirmed attacks (§13). Centrality outputs are used for prioritization, never as proof of compromise.

## Future Migration Path

The graph package exposes a traversal interface. Probabilistic inference (pending telemetry data) and exact betweenness are drop-in replacements. Graph persistence/store choice is deferred to benchmarks (ADR-0003 future path).
