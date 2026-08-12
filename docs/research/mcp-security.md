# MCP Security Research

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. MCP Protocol Model

**Claim:** The Model Context Protocol defines a client-server architecture in which AI applications (clients) connect to servers exposing tools, resources, and prompts over transports (stdio for local servers, HTTP/SSE/Streamable HTTP for remote servers).
**Evidence:** modelcontextprotocol.io official specification site; the spec is versioned by date (2025-06-18 release, plus a living draft). The architecture page failed text extraction twice in testing; the transport model is confirmed via the spec repository and the security best practices page.
**Source type:** Tier 1
**Confidence:** HIGH for stdio vs HTTP transport distinction; the full architecture page is marked UNVERIFIED and will be re-checked at implementation time
**Implementation impact:** `riskx mcp scan` treats local (stdio-launched) and remote (HTTP) MCP servers as distinct trust domains with different scan behaviors. Protocol assumptions are versioned (MCP 2025-06-18 / draft) in findings.

## 2. Trust Boundaries and the Confused Deputy

**Claim:** The MCP specification's security best practices document the confused deputy problem: an MCP proxy with a static client_id can cause a remote server to act on behalf of the wrong client; per-client consent is required, token passthrough without audience validation (RFC 9068) is an anti-pattern, and OAuth 2.0 deployment best practices (RFC 9700) are referenced.
**Evidence:** modelcontextprotocol.io/specification/draft/basic/security_best_practices (verified live extraction on 2026-08-12).
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** MCP findings classify confused-deputy configurations (shared client_id, missing audience validation, consent gaps) as distinct finding types with the spec page cited.

## 3. OWASP MCP Top 10

**Claim:** OWASP maintains an MCP Top 10 project (version v0.1, beta phase as of 2026-08-12; next release expected October 2026). The ten risks are MCP01 Token Mismanagement & Secret Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool Poisoning, MCP04 Software Supply Chain Attacks & Dependency Tampering, MCP05 Command Injection & Execution, MCP06 Intent Flow Subversion (prompt injection via contextual payloads), MCP07 Insufficient Authentication & Authorization, MCP08 Lack of Audit and Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection & Over-Sharing. License: CC BY-NC-SA 4.0.
**Evidence:** owasp.org/www-project-mcp-top-10 (verified live, Tier 1).
**Confidence:** HIGH
**Implementation impact:** Every MCP finding maps to one or more MCP01-MCP10 identifiers. The v0.1-beta volatility means mappings carry a version tag and must be re-verified when v0.2 ships.

## 4. What Can Be Safely Observed

**Claim:** An MCP scanner can legitimately observe: server identity/configuration files (e.g., Claude Desktop config, VS Code settings), tool catalogs returned by servers over allowed transports, tool metadata (schemas, descriptions), declared authentication arrangements, network location, package dependencies (npm/pypi listings), and code-repository evidence of server implementations. It cannot and must not attempt unauthorized credential extraction or tool invocation beyond what the configured client legitimately does.
**Evidence:** Spec §17 (binding requirement) combined with the transport model in §1 above.
**Confidence:** HIGH
**Implementation impact:** `riskx mcp scan` operates in PASSIVE mode by default: static analysis of config files and dependencies plus read-only tool-catalog introspection where the user's own client credentials are configured. Active tool invocation requires SAFE/VALIDATION mode with explicit consent.

## 5. Version Assumption Discipline

**Claim:** MCP implementations do not all behave identically; transport availability, auth mechanisms, and tool behavior vary by implementation and spec version.
**Evidence:** Spec §4 and §17 (binding requirements); the spec itself is versioned by date with a draft track.
**Confidence:** HIGH
**Implementation impact:** The scanner never assumes behavior beyond the verified spec version. Findings note the implementation (vendor/product) where determinable and the assumed spec version.
