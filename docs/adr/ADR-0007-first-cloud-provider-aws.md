# ADR-0007: First Cloud Provider — AWS (Phase 7 Candidate)

**Status:** Proposed — takes effect in Phase 7; recorded now per specification §18 and §38 (every major decision gets an ADR)
**Date:** 2026-08-12

## Context

The specification (§18) requires phasing cloud security and choosing the first provider based on API availability, open-source ecosystem, security relevance, documentation, implementation feasibility, and user demand, with every control's semantics verified against official documentation before support.

## Problem

Select the first cloud provider for the `riskx cloud` engine.

## Options Considered

1. **AWS** — largest OSS posture-checking ecosystem (Prowler Apache-2.0, ScoutSuite GPL-2.0), mature public IAM policy grammar and API surface, dominant market share, extensive Tier 1 documentation. Trade-off: IAM API complexity.
2. **Azure** — strong enterprise relevance. Trade-off: smaller OSS scanner ecosystem; Graph API and RBAC models require separate verification work.
3. **GCP** — clean API design. Trade-off: smallest OSS ecosystem of the three.

## Evidence

Ecosystem evidence in cloud-security.md §3 (Tier 1 repositories verified at access date); shared-responsibility documentation at Tier 1 provider pages; SCuBA precedent shows CISA's own tools target SaaS first, leaving cloud-IaaS posture to provider-specific ecosystems.

## Decision

AWS is the Phase 7 first provider, contingent on control-by-control verification against AWS documentation at implementation time. No AWS support ships in MVP; the CloudPlugin interface exists from Phase 1 so cloud-asset evidence ingests like any other source.

## Trade-offs

Accepted: Azure/GCP users wait for later phases. Mitigated: the plugin interface is provider-agnostic; adding providers does not rework the core.

## Security Implications

All cloud checks are read-only by default (SAFE mode semantics, §8); credentials enter only via user-configured profiles and are never logged or transmitted.

## Future Migration Path

Azure and GCP plugins follow the same interface; multi-cloud aggregation is a Phase 11 candidate once single-provider semantics are stable.
