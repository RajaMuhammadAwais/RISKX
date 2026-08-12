# Threat Model: RISKX Itself

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12
**Method:** STRIDE applied to the RISKX data flows identified in spec §25. This threat model covers the MVP attack surface; each new feature phase must extend it before implementation (spec §42 loop).

## 1. Assets to Protect

RISKX holds: configuration files (potentially containing API keys), cached vulnerability data, the local SQLite database of assets and findings, evidence records, generated reports, and logs. The user's environment (networks, credentials the user chooses to provide) must never be harmed by the tool.

## 2. Trust Boundaries and STRIDE Summary

| # | Flow | Trust boundary | Threats (STRIDE) | MVP mitigations |
| --- | --- | --- | --- | --- |
| T1 | User → CLI input (targets, flags) | CLI process | Spoofing/Tampering: injection via crafted target strings | Input validation; no shell construction from inputs (no `exec` with untrusted strings); stable-ID generation |
| T2 | RISKX → authoritative feeds (NVD/KEV/EPSS/OSV) | Network | Spoofing/Tampering: MITM; Information: feed data poisoning | TLS verification only (spec §25); schema validation of every response; feed-hash verification where signed; feeds never executed as code |
| T3 | Feed data → cache/DB | Process | Tampering: poisoned feed content processed as logic | Data treated as data, never eval'd; content addressed by checksums; stale marking on fetch failure |
| T4 | RISKX → target network (discovery) | Network | Elevation: tool performing more than user intended | PASSIVE default; mode flag gates behavior; SAFE mode uses read-only methods only; VALIDATION requires explicit authorization with pre-execution plan (spec §8) |
| T5 | Config files (secrets, API keys) | Filesystem | Information disclosure: config readable by others | File permissions 0600 on write; secret redaction in logs; credential isolation (separate env/config paths) |
| T6 | Reports/logs | Filesystem/Disk | Information disclosure: findings leak; log injection | Secure file permissions; secret redaction; structured logging without user-controlled format strings |
| T7 | Plugins (future) | Process | Elevation/Tampering: malicious or broken plugin | Plugin interface versioning; capability declarations; out-of-process execution model available (ADR-0006); no plugins ship in MVP |
| T8 | Dependency updates | Supply chain | Tampering: compromised dependency | Dependency pinning (go.sum); vetted dependency list; minimal dependency set; no arbitrary shell execution in build |
| T9 | Update mechanism (future Phase 11) | Network | Spoofing: fake release binary | Signed releases + checksum verification only; no autoupdate in MVP |

## 3. Highest-Priority Risks for MVP

**Claim:** The three MVP-critical risks are (1) injection through crafted inputs into any subprocess or template, (2) silent degradation when feeds fail (treated as security failure because stale data masquerading as current is worse than an explicit error), and (3) credential leakage through config files and logs.
**Evidence:** spec §25 mitigation list (credential isolation, secure file permissions, TLS verification, input validation, dependency pinning, safe temp files, secure logging, secret redaction, path traversal protection, command injection protection) and spec §48 failure behavior.
**Confidence:** HIGH (binding requirements)
**Implementation impact:** These map to concrete engineering controls: no `os/exec` with interpolated inputs (use typed client libraries), explicit feed-staleness values in output metadata, 0600 config writes with path-traversal checks, and a redaction layer in the logger.

## 4. Out of Scope for MVP (tracked)

Plugin isolation depth (T7) requires the plugin runtime that MVP does not ship; signed updates (T9) belong to Phase 11. Both are recorded here so they are not forgotten, per the continuous-research obligation (§51).

## 5. Safe-Use Constraints

RISKX performs discovery and assessment only against targets the operator explicitly configures. Findings are evidence-based observations with stated confidence — never confirmed exploitation claims. Active validation is an explicit, pre-announced mode. RISKX never tests systems without authorization (spec §28).
