# ADR-0006: Plugin System — Go Interfaces with Out-of-Process Option

**Status:** Accepted
**Date:** 2026-08-12

## Context

The specification (§22) requires plugin interfaces for Discovery/Asset/Vulnerability/Cloud/Identity/Agent/MCP/Risk/Reporter/Exporter, each with version, capabilities, configuration, permissions, logging, and error handling, and forbids tight coupling of scanners to the core engine.

## Problem

Design the plugin mechanism balancing isolation, compatibility, and implementation cost.

## Options Considered

1. **Go interfaces (in-process)** — simple, fast, type-safe, zero IPC. Trade-off: a misbehaving plugin can crash or compromise the host process; Go's lack of stable ABI means compiled plugins (golang.org/x/exp/shadow-like mechanisms) are not cross-version portable.
2. **golang.org/x/sys or plugin package (dlopen)** — true dynamic loading. Trade-off: platform and Go-version coupled; historically fragile; unsafe surface for untrusted code. Rejected.
3. **Out-of-process (exec-based) plugins** — strongest isolation; hashicorp/go-plugin pattern. Trade-off: IPC overhead; distribution of plugin binaries; not needed before third-party plugins exist.

## Evidence

Go plugin package limitations documented in Tier 1 Go documentation; go-plugin (HashiCorp) pattern documented at Tier 1 repository.

## Decision

MVP defines plugins as Go interfaces in pkg/plugins with in-process registration for built-in plugins. The interface design (method sets, capability manifests) anticipates an out-of-process transport; ADR-0006-R2 will add exec-based execution when third-party plugins are introduced. Plugin manifests declare version, capabilities, permissions, and license (ADR-0004).

## Trade-offs

Accepted: weaker isolation for built-in plugins. Mitigated: all MVP plugins are first-party, reviewed code; the registry's capability model limits what each plugin may access (network, filesystem, credentials) at the interface level.

## Security Implications

Capability declarations are enforced by the core runner, not trusted to plugins. Permissions model covers network egress, file access, and credential use per spec §25. Untrusted plugin code never runs in MVP.

## Future Migration Path

Interfaces are versioned (plugin-v1). Switching transports does not change plugin method signatures; the manifest gains a `runtime` field (in-process | out-of-process).
