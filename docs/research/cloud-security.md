# Cloud Security Research

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. Shared Responsibility Model

**Claim:** All three major providers define a shared responsibility model: the provider secures the cloud infrastructure; the customer retains responsibility for identity, data, configuration, and workload security. Misconfiguration of customer-managed controls is the dominant customer-side risk class.
**Evidence:** aws.amazon.com/compliance/shared-responsibility-model; learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility (Tier 1, both verified).
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** Cloud findings always attribute responsibility side (provider vs customer). RISKX assesses the customer side only, per the shared responsibility boundary.

## 2. CISA SCuBA and BOD 25-01

**Claim:** CISA's SCuBA project (2022) produces secure configuration baselines for Microsoft 365 and Google Workspace; ScubaGear (M365, PowerShell) and ScubaGoggles (GWS, Python/PyPI) are the open-source assessment tools on github.com/cisagov; BOD 25-01 enforces required cloud configurations for FCEB agencies.
**Evidence:** cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project (verified live).
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** SaaS misconfiguration assessment (a Phase 7+ candidate) should align with SCuBA baselines where applicable. SaaS is out of MVP scope.

## 3. CSPM / Cloud Posture Categories

**Claim:** CNAPP products bundle CSPM (posture), CWPP (workload), and CIEM (identity/entitlements); the open-source posture-checking ecosystem is strongest around AWS (Prowler, ScoutSuite, aws-iam-analyzer) because of AWS's public API surface and long-standing tooling ecosystem.
**Evidence:** Vendor and analyst literature (Tier 3); repository evidence: github.com/prowler-cloud/prowler (Apache-2.0, mature), github.com/nccgroup/ScoutSuite (GPL-2.0) — both verified to exist with the stated scopes.
**Confidence:** HIGH for ecosystem existence; MEDIUM for comparative maturity claims
**Implementation impact:** AWS is the Phase 7 first-provider candidate: strongest OSS ecosystem, verifiable API surface, highest security relevance per market telemetry. Decision documented in ADR-0007; Azure and GCP deferred.

## 4. Implementation Boundaries (MVP)

**Claim:** No cloud control should be checked until its semantics are verified against official provider documentation; IAM, network exposure, storage exposure, security groups, public resources, logging, secrets, and key management are the verified control classes for the eventual cloud plugin.
**Evidence:** Spec §18 (binding requirement); AWS official documentation and IAM policy grammar.
**Implementation impact:** Each future cloud check is preceded by a documentation verification step and a fixture-based test. Cloud exposure checks are out of MVP (Phase 7), but the plugin interface must exist from Phase 1 so the engine can ingest cloud-asset evidence like any other source.

## 5. AI/LLM Workload Exposure in Cloud

**Claim:** Cloud providers now expose AI services (Bedrock, Azure AI Foundry, Vertex AI) and AI-agent hosting; exposed AI endpoints are a distinct exposure class combining cloud-misconfiguration risk with AI-agent risk.
**Evidence:** Official provider AI service documentation (Tier 1); this intersection motivates the AI-endpoint and MCP-endpoint discovery targets in spec §9.
**Confidence:** HIGH for service existence; the risk taxonomy for exposed AI endpoints is an emerging area (MEDIUM)
**Implementation impact:** Discovery produces asset kinds `ai_endpoint` and `mcp_endpoint` with their own evidence rules; scoring for them uses ai-agent-security.md taxonomies.
