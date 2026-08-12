# ADR-0001: Implementation Language — Go

**Status:** Accepted
**Date:** 2026-08-12

## Context

RISKX is a network-oriented security CLI requiring concurrency, cross-platform distribution, and low operational overhead. The specification (§6) recommends Go but explicitly forbids accepting that recommendation without documented evaluation.

## Problem

Choose the primary implementation language for RISKX.

## Options Considered

1. **Go** — static single-binary distribution, goroutine concurrency, mature net/http/tls stack, precedent in security tooling (Docker, Kubernetes, Trivy, Prowler v2), cobra CLI framework. Trade-off: larger binaries than Rust, GC pauses acceptable for CLI workloads.
2. **Rust** — strongest safety guarantees, static binaries. Trade-off: longer development cycles for networking/concurrency code in early phases; smaller security-CLI ecosystem; higher implementation risk for MVP velocity.
3. **Python** — fastest prototyping. Trade-off: interpreter distribution friction, GIL limits parallel scanning, packaging per-platform — incompatible with "portable binaries" and "low operational overhead" requirements.

## Evidence

Evaluation table in docs/research/technology-evaluation.md §1. Go's security-tooling precedent is verified from Tier 1 repositories; language guarantees verified from official documentation.

## Decision

Go is selected. Rust remains a candidate for performance-critical future components (e.g., bulk network scanning) behind stable interfaces; Python remains a candidate for RAG/reporting utilities behind plugin interfaces.

## Trade-offs

Accepted: larger binary size, GC behavior. Mitigated: MVP stays single-user CLI-scale where GC impact is negligible.

## Security Implications

Go's standard library provides TLS-verified HTTP clients by default, satisfying §25 requirements. Its lack of a stable ABI pushes plugin isolation design to out-of-process models (ADR-0006) rather than dlopen-style shared libraries, which is safer for untrusted plugin code.

## Future Migration Path

Plugin interfaces (pkg/plugins) isolate language-specific components. A Rust scanner binary can be integrated as an out-of-process plugin without changing interfaces.
