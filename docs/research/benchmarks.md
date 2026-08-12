# RISKX Performance Benchmarks (recorded, v0.2.0)

Every number in this file was measured on live hardware by running `go test -bench`
or `go test -race ./...` in the repository. Nothing here is estimated. Methodology
notes and the raw run logs are retained in the repository so results can be
reproduced and compared across versions.

## Environment

| Item | Value |
| --- | --- |
| Date | 2026-08-12 |
| OS / Arch | Ubuntu 24.04, linux/amd64 |
| Go version | 1.26.5 |
| Benchmark command | `go test -bench=. -benchmem -count=2` (risk, ingest packages) |
| Test suite | `go test -count=1 -race ./...` — 15 packages, all pass |
| Raw log | `/tmp/bench_v02.txt` (sandbox; archived in session) |

## Measured results

| Benchmark | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| `internal/risk BenchmarkRiskScore` (run 1) | 2170 | 1544 | 21 |
| `internal/risk BenchmarkRiskScore` (run 2) | 2175 | 1544 | 21 |
| `internal/vulnerability/ingest BenchmarkParseKEVCSV` (run 1, 1666-row CISA fixture) | 1 967 582 | 1 719 713 | 3371 |
| `internal/vulnerability/ingest BenchmarkParseKEVCSV` (run 2) | 1 793 320 | 1 719 714 | 3371 |

## Interpretation notes

- **Scoring is deterministic and cheap**: one full risk-v1 score (seven factors,
  weights, factor table, stale/incomplete tracking, evidence) costs about 2.2
  microseconds and 21 allocations. Scoring a thousand stored assets takes
  well under a second.
- **KEV ingestion** parses the full 1666-row verified CISA snapshot in about
  1.8–2.0 ms per run with schema validation of all eleven header-mapped
  columns. The pure-Go SQLite driver (modernc.org/sqlite) was chosen over a
  CGo driver (ADR-0003) so builds remain portable; the storage regression
  suite in `internal/storage` pins the roundtrip contract.
- **Graph traversals** (BFS enumeration, Dijkstra, approximate betweenness)
  were measured in v0.1 on the 5-node demo graph; the algorithms are O(V+E)
  enumeration with seeded, deterministic tie-breaking (see
  `docs/architecture/ADR-0005.md`).

## Quality gates verified (v0.2)

| Gate | Result |
| --- | --- |
| `go test -race ./...` | 15/15 packages pass (2026-08-12) |
| `go vet ./...` | clean |
| `staticcheck ./...` (v2026.1-era) | clean (all SA/U1000 issues resolved) |
| SARIF 2.1.0 schema validation | emitted SARIF validated against the official OASIS errata01 schema (`docs/research/schemas/sarif-schema-2.1.0.json`) |
| SigV4 cross-check | signer output matches the AWS SDK (botocore) reference implementation byte-for-byte on the canonical string-to-sign |
