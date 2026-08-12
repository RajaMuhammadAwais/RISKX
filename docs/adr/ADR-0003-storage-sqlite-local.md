# ADR-0003: Storage — Embedded SQLite for Local CLI

**Status:** Accepted
**Date:** 2026-08-12

## Context

RISKX MVP is a single-user local CLI. The specification (§23) requires a storage evaluation across SQLite, PostgreSQL, Neo4j, and embedded graph stores, and explicitly treats the "SQLite local / PostgreSQL server / graph store" architecture as a hypothesis to be benchmarked.

## Problem

Choose MVP storage for asset inventory, findings, evidence, and cached feed data.

## Options Considered

1. **SQLite (embedded)** — zero-install, single-file, mature, ACID, portable; pure-Go driver option avoids CGO for cross-compilation. Trade-off: single-writer; not suited to future multi-tenant server mode.
2. **PostgreSQL** — multi-user, scalable. Trade-off: requires an external server — incompatible with "low operational overhead" for a local CLI; premature for MVP data volumes.
3. **Neo4j / embedded graph stores** — native graph semantics. Trade-off: heavy runtime for MVP-scale graphs; the graph engine (in-memory, bounded scope) covers Phase 5 needs; benchmark-driven decision deferred per §23.

## Evidence

SQLite documentation (Tier 1); architecture-v1.md §7 notes graph state is in-memory in MVP with a tracked persistence decision. Database choice is labeled hypothesis-until-benchmarked in technology-evaluation.md §3, and this ADR commits to SQLite only for the local-CLI role, keeping the server-mode path open.

## Decision

SQLite, embedded, with the pure-Go driver preferred for cross-platform static builds. Migrations managed in internal/storage with schema version `storage-v1`.

## Trade-offs

Accepted: single-writer limitation; manual graph persistence. Mitigated: MVP operates single-user; graph persistence revisited with benchmarks in Phase 5+.

## Security Implications

Database file written with 0600 permissions (spec §25 secure file permissions); the file stays on the operator's machine (no external transmission, §46); findings never contain raw secrets (redaction layer, §25).

## Future Migration Path

Schema versioning isolates storage internals. A PostgreSQL backend behind the same repository interface supports the eventual server mode (Phase 11); a graph store behind the graph interface supports Phase 5+ scaling, pending benchmarks.
