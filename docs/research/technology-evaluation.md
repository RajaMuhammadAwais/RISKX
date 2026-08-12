# Technology Evaluation

**Status:** Phase 0 research — complete
**Access date:** 2026-08-12

## 1. Implementation Language: Go vs Rust vs Python

**Claim:** Go is the recommended primary language because RISKX requires networking, concurrency, portable static binaries, low operational overhead, cross-platform execution, and strong CLI tooling; Rust and Python are alternatives with different trade-offs.
**Evidence:**
| Criterion | Go | Rust | Python |
| --- | --- | --- | --- |
| Concurrency model | goroutines/channels, battle-tested in network tooling | async + fearless concurrency, steeper learning curve | threading/asyncio, GIL limits CPU parallelism |
| Binary portability | Single static binary, cross-compile trivial | Static binary, longer build times | Interpreter required per platform |
| Ecosystem | cobra/urfave-cli, standard net/http/tls packages mature | tokio/hyper mature but younger security-tooling ecosystem | rich CLI libs, but deployment and distribution heavier |
| Security tooling precedent | Docker, Kubernetes, Trivy, Prowler v2 — all Go | ruffle, some eBPF tooling — fewer CLI scanners | bandit, safety — analysis tools rather than scanners |
| Team velocity for this project | High | Lower initially | High initially, maintenance risk later |
**Source:** Language documentation (Tier 1: go.dev, rust-lang.org, python.org); precedent projects (Tier 1 repositories)
**Confidence:** HIGH
**Implementation impact:** Go selected (ADR-0001). Decision is revisitable via ADR mechanism if evidence changes.

## 2. CLI Framework

**Claim:** Cobra (spf13/cobra) with pflag provides command trees, `--help` generation, and POSIX flag semantics matching the required command set (init, version, config, doctor, discover, assets, scan, vuln, cloud, identity, ai/agent/mcp scan, graph, attack-path, risk, report, export, policy, validate, continuous).
**Evidence:** spf13/cobra README and documentation; widespread use in Go security CLIs (Trivy, Docker CLI). License MIT.
**Source type:** Tier 1 (official repository)
**Confidence:** HIGH
**Implementation impact:** Cobra selected (ADR-0002). Every command exposes --help, --version, --output, --config, --quiet, --verbose, --json per spec §7.

## 3. Storage: SQLite vs PostgreSQL vs Graph Stores

**Claim:** The recommended architecture is SQLite for the local CLI (zero-install, file-based), PostgreSQL for eventual server/enterprise deployment, and either an embedded graph model over SQLite or a dedicated graph store for attack-path analysis; the exact choice is a hypothesis until benchmarked.
**Evidence:** Spec §23 (the repository structure is a hypothesis pending benchmarks); SQLite's file-based design suits a single-user CLI; Neo4j and embedded graph options (e.g., arangodb/embedded options) exist but add deployment weight.
**Source type:** Tier 1 (database documentation) + spec constraint
**Confidence:** HIGH for SQLite fit; MEDIUM for graph-store selection (unbenchmarkd)
**Implementation impact:** MVP stores assets/findings/evidence in SQLite via mattn/go-sqlite3 or modernc.org/sqlite (pure-Go driver preferred for cross-compile simplicity — verified at implementation time). Graph traversal runs in-memory over an adjacency structure for MVP scope; persistence of graph state is deferred.

## 4. Graph Algorithms and Engine

**Claim:** For MVP-scale graphs (single-scan scope, thousands of nodes), an in-memory adjacency representation with Dijkstra-style weighted traversal and BFS enumeration is sufficient; a dedicated graph database is premature.
**Evidence:** attack-path-analysis.md (algorithm research); the state-space-expllosion caution in the same document bounds MVP scope.
**Confidence:** HIGH for MVP scope; MEDIUM for large-inventory scaling (unbenchmarkd — belongs in §29 benchmark suite)
**Implementation impact:** Graph engine is a plain Go package with a documented edge-status model (ADR-0005). Migration path to a graph store is part of the ADR.

## 5. Plugin System

**Claim:** Plugins are Go interfaces (DiscoveryPlugin, AssetPlugin, VulnerabilityPlugin, CloudPlugin, IdentityPlugin, AgentPlugin, MCPPlugin, RiskPlugin, ReporterPlugin, ExporterPlugin) registered at startup, each carrying version, capabilities, configuration, permissions, logging, and error handling. Out-of-process plugins (e.g., hashicorp/go-plugin) are the safer isolation model for untrusted code.
**Evidence:** spec §22 (binding interface list); go-plugin documentation; Go's absence of a stable ABI precludes plain shared-library plugins for cross-version compatibility.
**Source type:** Tier 1 (plugin repo docs)
**Confidence:** HIGH
**Implementation impact:** Plugin interfaces defined in pkg/plugins from Phase 1 (ADR-0006). Isolation level (in-process interface vs out-of-process exec) is versioned and may be upgraded without breaking the interface.

## 6. Output Formats

**Claim:** CLI human output, JSON, JSONL, CSV, and SARIF are required; SARIF v2.1.0 (OASIS) is the current specification to implement, with its schema verified at implementation time.
**Evidence:** spec §31 (binding list); oasis-open.github.io/sarif-spec (Tier 1) — version to be re-verified during Phase 11.
**Confidence:** HIGH for the format list; MEDIUM for SARIF version until re-verified
**Implementation impact:** JSON schema is the internal canonical format; other formats are serializers over it (ReporterPlugin/ExporterPlugin).

## 7. Supply-Chain Tooling

**Claim:** SPDX and CycloneDX are the two SBOM standards; Sigstore/Cosign provide signature and provenance tooling; SLSA v1.0 is the final provenance framework; in-toto underlies Sigstore provenance.
**Evidence:** spdx.dev, cyclonedx.org, sigstore.dev, slsa.dev (Tier 1 foundation sites). SLSA v1.0 final status verified on slsa.dev.
**Source type:** Tier 1
**Confidence:** HIGH
**Implementation impact:** Phase 11 delivers: SBOM generation (CycloneDX chosen for richer dependency metadata — decision to re-verify at implementation), Go module dependency pinning (go.sum), GoReleaser + Cosign signing, and checksum manifests. Nothing here enters MVP.

## 8. AI Provider Abstraction

**Claim:** An optional AI layer uses interfaces (LLMProvider, EmbeddingProvider, RerankerProvider) so no vendor is coupled into the core; the scanner must remain fully functional without any LLM configured.
**Evidence:** spec §47 (binding requirement).
**Confidence:** HIGH
**Implementation impact:** AI is a plugin with a default "none" implementation. RAG (Phase 10) retrieves only from verified knowledge sources with preserved citations (spec §21).

## 9. Failure and Privacy Defaults

**Claim:** Default behavior is privacy-preserving (no external transmission of asset data, credentials, findings), telemetry OFF by default, and all feeds are marked stale rather than silently trusted when unavailable.
**Evidence:** spec §46, §48 (binding requirements).
**Confidence:** HIGH
**Implementation impact:** No telemetry code exists in MVP; network calls are outbound-only to authoritative feeds; failure states are first-class values in the evidence model.
