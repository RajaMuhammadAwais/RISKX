# AI-Agent Security Research

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. Primary-Source Framing

**Claim:** NIST's current agent-security material is distributed across the AI RMF (AI 100-1), the Generative AI Profile (AI 600-1), the draft Misuse Risk publication (AI 800-1 ipd2), SP 800-218A, and the in-progress COSAiS project. A finalized agent-specific control overlay does not exist yet.
**Evidence:** csrc.nist.gov/projects/cosais lists agent overlays (use cases 3-4) as proposed work without final publications as of 2026-01-08 update. AI 100-1 and AI 600-1 are final and reachable at nist.gov and nvlpubs.nist.gov.
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** RISKX agent-risk findings cite AI RMF functions and AI 600-1 categories as the authoritative vocabulary. The product does not claim compliance with nonexistent agent overlays.

## 2. Agent Identity, Authorization, and Auditing (NIST 2026 Work)

**Claim:** NIST's 2026 AI-agent security work emphasizes agent identity, authorization, auditing, non-repudiation, and prompt-injection-related controls; the CAISI AI Agent Standards Initiative (launched 2026-02-17) is the first U.S. government program targeting agentic AI interoperability and security standards; the NCCoE concept paper (2026-02-05) focuses on agent identification, OAuth 2.0 extension authorization, delegation accountability, and logging/transparency.
**Evidence:** CSA analysis of the NIST AI agent standards landscape (Tier 3 secondary), cross-checked against the existence of the CAISI initiative and NCCoE concept paper (Tier 1 references).
**Source type:** Tier 3 with Tier 1 cross-checks; headline figures (81% vs 11% hijacking success) from the cited NIST/UK AISI study via Tier 3 source
**Confidence:** MEDIUM (initiative existence HIGH; detailed claims MEDIUM pending direct primary-document verification)
**Implementation impact:** The agent risk model's Identity/Authorization/Auditability dimensions map to the NCCoE focus areas. Delegation and accountability become explicit agent-asset attributes.

## 3. OWASP Agentic AI Security Guidance

**Claim:** OWASP publishes agentic-AI security guidance; its agent-risk categories (excessive agency, prompt injection, indirect prompt injection, tool poisoning, memory security, insecure workflows, impersonation, supply chain) form the taxonomy RISKX uses for agent findings.
**Evidence:** owasp.org project pages for agentic AI (OWASP Top 10 for LLM Applications 2025, which added agentic categories) and the Agentic AI security project.
**Source type:** Tier 1 (OWASP)
**Confidence:** HIGH for the category list as published; version specifics should be re-verified at implementation time because OWASP releases evolve
**Implementation impact:** Agent findings carry `owasp_llm_top10_2025` and `agentic_ai` classification fields alongside ATT&CK-style technique references.

## 4. Framework Detection Feasibility

**Claim:** Detecting which agent framework (LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Anthropic architectures, custom, RAG, tool-using, multi-agent) an application uses is possible from dependency files, runtime configuration, and process/network evidence, but not guaranteed; undetectable cases must be reported as INSUFFICIENT EVIDENCE rather than guessed.
**Evidence:** Frameworks expose identifying artifacts: Python requirements/lockfiles name langgraph, crewai, autogen; OpenAI Agents SDK names openai-agents; Anthropic's agent patterns appear in code and MCP tooling; MCP endpoint presence is detectable via well-known endpoint conventions (see mcp-security.md).
**Source type:** Tier 1 (official framework documentation/repositories)
**Confidence:** HIGH for dependency-file detection; MEDIUM for runtime inference
**Implementation impact:** Agent discovery reports `method`, `evidence`, and `confidence` per spec §15. Detection without evidence is prohibited; absent evidence produces INSUFFICIENT EVIDENCE, never a framework guess.

## 5. Agent Risk Dimensions

**Claim:** Agent risk assessment evaluates identity, authorization, tool access, data access, execution capability, network access, secrets access, memory, external communication, human approval, autonomy, auditability, and isolation.
**Evidence:** Spec §16 (binding requirement); consistent with OWASP agentic categories and NIST/NCCoE focus areas.
**Implementation impact:** The agent capability graph (agent → capability → resource) is the Phase 8 data structure. Excessive agency is concluded only from capability-vs-role comparison with evidence, never from tool existence alone.

## 6. What Is NOT Yet Established

**Claim:** There is no standalone, finalized federal agentic-AI security standard; multi-agent lateral movement and reasoning-layer attacks lack dedicated MITRE techniques; quantitative agent-risk scoring is an emerging academic area.
**Evidence:** NCCoE concept paper (2026-02-05) states the gap; ATT&CK v19.2 release notes; risk-model.md.
**Confidence:** HIGH (gap existence), MEDIUM (implications)
**Implementation impact:** RISKX documents these gaps, uses the best available vocabulary (AI RMF + OWASP + OWASP MCP Top 10), and versions its agent-risk model separately (`agent-risk-v1`).
