# ADR-0004: Dependency and License Policy

**Status:** Accepted
**Date:** 2026-08-12

## Context

RISKX is a security tool whose own supply chain must be trustworthy (§25-26 of the specification). The open-source discovery ecosystem contains components under different licenses (e.g., zmap/masscan are GPL-2.0; SubFinder and Amass are MIT with third-party clauses; Awesome-Asset-Discovery is CC0).

## Problem

Define which dependencies and licenses are acceptable, and how discovery capabilities are implemented without license contamination of the core.

## Options Considered

1. **Import existing OSS scanners as libraries** — fastest. Trade-off: GPL-licensed code (zmap, masscan) would impose copyleft obligations on a distributed binary; third-party clauses in MIT code require per-file review. Rejected for the core.
2. **Invoke external CLI tools as subprocesses** — avoids linking. Trade-off: shell-subprocess composition conflicts with §24's "no arbitrary shell execution" and "no unsafe command construction" prohibitions; adds deployment coupling. Rejected for MVP.
3. **Implement discovery logic in-house using verified protocol behavior** — full control, license-clean. Trade-off: more implementation work; must verify protocol semantics against primary sources (enforced by the research quality gate, §41).

## Evidence

License facts verified from official GitHub repositories (Tier 1) at access date; GPL-2.0 and MIT license texts at spdx.org (Tier 1).

## Decision

The core implements its own networking/DNS/TLS/HTTP logic (Phase 2) using only license-compatible dependencies (MIT/BSD/Apache-2.0/UNLICENSE, reviewed case-by-case). No GPL-licensed code is linked into the core binary. External scanners may later be integrated as out-of-process plugins with explicit license declarations in plugin manifests.

## Trade-offs

Accepted: reinvention cost for DNS/TLS fingerprinting code. Mitigated: logic is protocol-based (RFC-verified behavior) and covered by fixtures/tests; the research notes already record verified endpoint behaviors (e.g., DNS-over-UDP/TCP, TLS handshake semantics).

## Security Implications

Smaller, reviewed dependency set reduces supply-chain surface (§26). Pinned dependencies via go.sum; dependency-vulnerability checks in CI gate (§24 tooling).

## Future Migration Path

Plugin manifests declare licenses; the registry can enforce allowlists. Server-mode or specialized scanners may adopt heavier dependencies behind plugin isolation.
