# ADR-0002: CLI Framework — cobra (+pflag)

**Status:** Accepted
**Date:** 2026-08-12

## Context

The specification (§7) requires a command tree (init, version, config, doctor, discover, assets, scan, vuln, cloud, identity, ai, agent, mcp, graph, attack-path, risk, report, export, policy, validate, continuous) with per-command flags --help, --version, --output, --config, --quiet, --verbose, --json.

## Problem

Choose a CLI framework that supports nested commands, global flags, and help generation.

## Options Considered

1. **cobra + pflag** — de facto Go standard for nested CLIs; used by Docker, Kubernetes, Trivy; automatic --help; POSIX flag semantics; MIT license.
2. **urfave/cli/v3** — simpler flat/hierarchical API, smaller footprint. Trade-off: less established for large command trees; v3 API still maturing.
3. **hand-rolled** — full control. Trade-off: re-implements help/flag semantics; violates DRY; higher maintenance.

## Evidence

spf13/cobra documentation and adoption record (Tier 1 repository, MIT); precedent in Tier 1 security CLIs.

## Decision

cobra with pflag. Global flags (config, verbose, quiet, json, output, version) are attached to the root command; subcommands add domain flags (mode, targets, formats).

## Trade-offs

Accepted: cobra's dependency surface (yaml.v3, pflag — all widely used, license-compatible). Mitigated: dependency pinning via go.sum and quarterly vulnerability checks.

## Security Implications

Framework choice has minimal security surface; flag parsing is well-tested. The security-critical controls (mode gating, input validation) live in internal/core, not the framework.

## Future Migration Path

Low risk; command handlers are framework-agnostic functions. Switching frameworks would touch cmd/ only.
