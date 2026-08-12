# Phase Progress Tracker (internal)

Repo: /home/ubuntu/RISKX (private GitHub RajaMuhammadAwais/RISKX). Go installed at /usr/local/go/bin + ~/go/bin (source scripts/setup_env.sh). golangci-lint v2.1.6 installed via scripts/setup_env.sh.

## Phase 0 — DONE (all files written)
- docs/research/: README.md, research-index.md, ctem.md, vulnerability-intelligence.md,
  attack-path-analysis.md, risk-model.md, standards.md, ai-agent-security.md,
  mcp-security.md, cloud-security.md, competitive-analysis.md, technology-evaluation.md,
  threat-model.md (+ internal _notes.md, _spec_map.md)
- docs/architecture/architecture-v1.md
- docs/adr/: ADR-0001 (Go), ADR-0002 (cobra), ADR-0003 (SQLite), ADR-0004 (deps/license),
  ADR-0005 (graph algorithms), ADR-0006 (plugin interfaces), ADR-0007 (AWS)
- Existing: LICENSE (Apache-2.0), SECURITY.md, go.mod, scripts/setup_env.sh,
  tests/fixtures/kev.csv, cmd/riskx (dir), internal/ dirs (dirs exist)

## STATUS (updated after Phase 1 start)
- todo.md WRITTEN (root of repo). All Phase 0 docs WRITTEN (research 13 files, architecture-v1, ADR-0001..0007).
- Phase 1 code: deps added (cobra, pflag, modernc.org/sqlite, yaml.v3). Written:
  pkg/models/models.go (Asset/Provenance/Fingerprint/Relationship/Finding/Classification/
  Vulnerability/EPSSReading/SourceCitation/Evidence/RiskScore/RiskFactor/FeedStatus/
  ScanMetadata/Suppression + Finding helpers InKEV/ExposureLevel/IsAdmin/ReferencesCVE,
  ContentID), internal/evidence/evidence.go (Source+Citation, preset sources CISAKEV/
  NVDAPI/FIRSTEPSS/OSVAPI/OWASPMCP/MCPSpec/OWASPTop10/CISControls/MITREATTACK),
  internal/core/errs/errs.go (RISKX typed errors + codes + StaleDataError +
  VisibilityIncompleteError + Input), internal/core/log/log.go (leveled redacting),
  internal/core/config/config.go (Default/Load/Save 0600, validatePath traversal,
  KnownFields strict yaml, ToolVersion 0.1.0, Feeds KEVStaleAfterDays=1 EPSS=7),
  internal/core/mode/mode.go (Passive/Safe/Active/Validation + Authorizer with
  action plan + CI preapprove), internal/core/output/output.go (Result/Printer,
  NVDAttribution constant, AddNVDAttribution, NewMeta), internal/core/idgen/idgen.go,
  internal/policy/policy.go (Policy/Rule/Condition/Evaluate, exit 0/1/2, suppressions
  honored, min_score/kev/internet_exposed_admin rules), internal/risk/risk.go
  (risk-v1 Engine, DefaultWeights sum=1 normalized, 7 factors, EPSSStaleDays=7,
  incomplete/stale tracking, band severity), pkg/plugins/plugins.go (Manifest,
  Permissions, Discovery/Vulnerability/Risk/Reporter/Exporter interfaces, Registry),
  internal/core/runner/runner.go (Command interface, Run with auth+policy+exit codes),
  cmd/riskx/main.go (root + 19 subcommands scaffolds), cmd/riskx/cmd_basic.go
  (version/init/config/doctor+checkKEVReachable), cmd/riskx/cmd_discovery.go
  (discover/scan/vuln/risk/assets — discovery wires to dns/http/tls pkgs, uses
  printer(cmd)/startedNow()/loadTargets()/splitCSV()/probePorts() helpers TO WRITE).
- Still to write in cmd/riskx: printer(cmd), startedNow, loadTargets, splitCSV,
  probePorts helpers (put in cmd/riskx/helpers.go). Internal/discovery/http and
  tls packages do not exist yet (dns.go references them) — write next, then
  go build fixes.
- Phase 1 remaining: unit tests (models/idgen/config/policy/risk/mode/output/runner),
  gofmt+go vet+staticcheck+golangci-lint clean, race detector. Then Phase 2
  (finish discover wiring: http.Inspect, tls.Inspect, probePorts, assets list,
  storage-v1 SQLite), Phase 3 (KEV/NVD/EPSS/OSV clients + risk wiring), Phase 4
  (risk cmd wiring), Phase 5 (graph + attack-path), Phase 6 (report/export/suppress),
  then benchmarks, README, push to GitHub.
- Go build currently: go build ./... compiles after writing http/tls pkgs and helpers.
  Setup: source /home/ubuntu/RISKX/scripts/setup_env.sh (go 1.26.5 at
  /usr/local/go/bin; golangci-lint v2.1.6).

## NEXT: todo.md (detailed, spec §50 MVP scope + roadmap), then README.md,
then implementation phases 1-5 per spec roadmap, then push to GitHub, deliver.

## Remaining plan phases (from current task plan)
- Phase 5 (write todo.md + README) — CURRENT
- Phase 6: Core CLI — go.sum deps (cobra, pflag, sqlite driver), internal/core
  (runner, modes, config, logging, errors, output helpers), pkg/models (asset/finding/
  evidence types asset-v1/finding-v1/evidence-v1), pkg/plugins interfaces,
  cmd/riskx root + commands init/version/config/doctor/discover/assets/scan/vuln/
  risk/graph/attack-path/report/export/policy/validate/continuous (stubs with flags),
  risk-v1 engine w/ factor table + version, --json + human output, exit codes 0/1/2.
- Phase 7: Asset discovery — DNS (system resolver, record types), HTTP (HEAD/GET with
  timeouts, TLS, banners), TLS cert parsing (SANs), WHOIS via RDAP (data.rdap.org —
  verify), provenance JSON per asset (asset/source/method/timestamp/confidence),
  asset inventory dedup + stable IDs, SQLite storage (mattn/go-sqlite3 or
  modernc.org/sqlite pure-go).
- Phase 8: Vuln intel — KEV CSV ingestion (fixture + live), NVD API 2.0 client
  (pagination, rate limit, attribution string required!), EPSS client, OSV client,
  CWE lookup (single-CWE endpoint only; top-25 UNVERIFIED), normalized Vulnerability
  model, caching with staleness flags.
- Phase 9: Risk engine + attack graph — risk-v1 scoring (7 factors, weights YAML,
  factor table output), evidence model, graph package (BFS enum + Dijkstra weighted,
  degree + approx betweenness centrality), edge statuses Observed/Inferred/Potential/
  Validated, path ranking output.
- Phase 10: Tests — unit/negative/fixtures/regression/fuzz/performance; golangci-lint,
  go vet, race detector, golden tests for risk-v1, fixtures from KEV snapshot.
- Phase 11: Push (git add/commit/push to RajaMuhammadAwais/RISKX), final README,
  deliver message.

## Key constraints to remember during implementation
- Every JSON output must include attribution "This product uses the NVD API but is not
  endorsed or certified by the NVD." when NVD data used.
- No shell exec with user inputs; TLS verify only; 0600 config files; PASSIVE default.
- Model versions: risk-v1, asset-v1, finding-v1, evidence-v1, plugin-v1, graph-v1,
  storage-v1. RISKX version 0.1.0.
- Exit codes: 0 no violation, 1 violation, 2 error.
- KEV fixture at tests/fixtures/kev.csv (1666 rows, 2026-08-12 snapshot).
- NVD bulk feeds return 403 — API only. EPSS: api.first.org/data/v1/epss?cve=X.
  OSV: api.osv.dev/v1/vulns/{id}. KEV: cisa.gov CSV URL in research docs.
- ATT&CK v19.2 (2026-08 spec date); tactic TA0005 Stealth / TA0112 Defense Impairment.
- MCP: version assumptions 2025-06-18/draft; OWASP MCP Top10 v0.1 (MCP01-MCP10).

## UPDATE mid-Phase 3 (Aug 12, 2026)
- Phase 1 COMPLETE: all packages built, tests pass with race detector, go vet + staticcheck clean.
- Phase 3 ingest COMPLETE: internal/vulnerability/ingest (KEV header-name-validated parser for the 11-column catalog: cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes), EPSS, OSV (GET /v1/vulns/{id}), NVD (rate-limited, with test Endpoint override). normalize.Fuse done. findings.CVEFinding done (uses models API: Finding{ID,Schema,AssetID,AssetValue,Title,Description,Observation,Evidence,Severity,Confidence,Status,Validation,References,CreatedAt,Remediation}; Evidence{Type,Source,Timestamp,Value,Citation(SourceCitation{Organization,Document,URL,Accessed})}; Remediation{Problem,WhyItMatters,Evidence,Fix,Verification,Rollback}; sev/conid consts: SevCritical|High|Medium|Low, ConfidenceHigh, StatusObserved|Inferred|Potential|Validated, ValidationUnvalidated|Pending|Validated|Failed, idgen.FindingID).
- Sandboxing: CISA KEV CSV 403 from sandbox; live tests gated by testing.Short() + RISKX_SKIP_FEEDS=1. KEV fixture tests/fixtures/kev.csv.
- NEXT: wire `riskx vuln` and `riskx risk` commands (cmd_discovery.go already has vuln/risk stubs — check cmd_analysis.go too), Phase 5 attack graph package, then tests/lint/README/push.
- Setup per shell: export PATH=$PATH:/usr/local/go/bin:/home/ubuntu/go/bin

## UPDATE (Phase 3 wiring)
- `riskx vuln CVE-ID...` now fully wired: normalize.Fuse + findings.CVEFinding, outputs vulnerabilities/findings/evidence JSON with NVD attribution. `riskx risk` wired to risk.NewEngine with demo asset.
- KEVClient now has local fallback (KEVLocalFixturePath=tests/fixtures/kev.csv when network fails), RISKX_KEV_CSV_URL env override, parseFile + fallback helpers.
- CURRENT FIXES NEEDED in internal/vulnerability/ingest/ingest.go (compile errors): (1) KEVCSVURL cannot be const since defaultKEVURL() is a function — change KEVCSVURL/KEVLocalFixturePath/KEVStaleAge/NVDUnauthRate block from `const (` to `var (` except KEVStaleAge/NVDUnauthRate/NVDRateWindow/EPSSStaleAge which are time.Duration/const ints — move env-based vars to separate var block. (2) add "os" to imports.
- After fix: rebuild, run tests (-short), smoke test `go run ./cmd/riskx vuln CVE-2021-44228 --json` (expect KEV=true via fixture fallback in sandbox; CISA 403s sandbox network).
- THEN: Phase 5 attack graph (internal/graph: BFS/Dijkstra/centrality per ADR-0005), Phase 4 risk cmd storage integration, findings tests, staticcheck, README, commit+push to RajaMuhammadAwais/RISKX.
- KEV fixture: tests/fixtures/kev.csv downloaded 2026-08-12 from CISA (1666+ rows). KEV known: CVE-2021-44228 in KEV.

## UPDATE (Phase 5 graph, current)
- internal/graph/graph.go DONE: Node/Edge/Path/Graph types, EdgeWeight (evidence-derived), EntryNodes/CrownNodes (from attached risk scores), BFSPaths (mode-gated enumeration, descending score), DijkstraPaths (min-cost to crowns, ascending), Degree + ApproxBetweenness (deterministic, seeded node order; normalize by max), CentralityReport, EdgeID (models.ContentID), ReportMode ObservedOnly/EvidenceBacked/Exploratory.
- Graph tests (graph_test.go) all pass except TestBetweennessIsDeterministic: db expected non-zero betweenness but got 0. BUG LOCATION: ApproxBetweenness BFS — `dist` map initialized only with src; loop iterates `adj[v]` but queue starts [src]. Suspect: edge From→To only; db has incoming edges (web→db, api→db, ssh→db) but NO outgoing edges → no path FROM db, so db betweenness = 0 (it has no successors in this directed graph; betweenness only counts paths THROUGH it when it's an intermediate node on others' shortest paths). web→db: db is endpoint not intermediate. web→api→db: intermediate is api. So db betweenness SHOULD be 0 in this graph! Test expectation wrong → fix test: expect db==0, expect api > 0 (api lies on web→api→db and web→api→admin paths).
- Also TestDegreeCentrality fixed to expect 0.75 (3/4).
- REMAINING after graph: cmd_analysis.go attack-path command wiring (uses graph pkg), findings normalize tests OK. Then findings/normalize tests for findings package if exists. Then Phase 10: staticcheck, benchmarks, race, lint; README; git add/commit/push to RajaMuhammadAwais/RISKX; deliver.
- KEV fixture works; vuln CLI fully functional; risk CLI functional with demo asset.
- Shell setup: export PATH=$PATH:/usr/local/go/bin:/home/ubuntu/go/bin (go 1.26 at /usr/local/go/bin).

## UPDATE (attack-path/graph command wiring + state)
- internal/graph DONE + all graph tests pass incl. race (10 suites green). Graph: BFSPaths/DijkstraPaths/degree/approxBetweenness/centrality/mode gating. api is pivot (betweenness>0); db is endpoint only.
- cmd_analysis.go NOW WIRED: newGraphCmd (list/centrality → demoGraph()), newAttackPathCmd top [n] with --mode flag (observed_only/evidence_backed/exploratory) using DijkstraPaths on demoGraph(); demoGraph() helper added (5 nodes: web,api,db,ssh,admin with RiskScore factors exposure+criticality+known_exploitation).
- NEXT STEPS: (1) build cmd (may need unused imports fmt in cmd_analysis — was used? fmt imported; verify), run go vet, staticcheck, full test suite w/ race. (2) Write findings/normalize tests if missing coverage. (3) README.md (tool overview, commands, evidence model, exit codes, NVD attribution, install from source). (4) todo.md progress updates (mark Phase 3/5 done). (5) git add -A, commit (first commit), push to RajaMuhammadAwais/RISKX. (6) deliver message.
- Note: cmd_analysis.go still imports "fmt" (used by validate actions?) — check build errors after wiring; validate cmd may have used fmt for plan printing.
- Binary smoke: `go run ./cmd/riskx vuln CVE-2021-44228 --json` works; `riskx discover google.com --json` works; KEV fixture fallback works in sandbox.
- KEV fixture: tests/fixtures/kev.csv (2026-08-12 snapshot from cisa.gov).
- Exit codes implemented via internal/policy; runner package does policy exit codes.
- Go env: export PATH=$PATH:/usr/local/go/bin:/home/ubuntu/go/bin; staticcheck available in ~/go/bin.

## UPDATE (post wiring smoke test, 2026-08-12)
DijkstraPaths smoke test shows ['admin'] score=0.00 — admin is BOTH a crown (criticality 0.8) AND an entry node (exposure 1.0), so Dijkstra distance to it is 0 with a one-node "path". This is technically correct per evidence (admin is exposed AND critical → direct risk), but looks odd; acceptable behavior: an internet-exposed critical asset IS a direct 0-hop risk. Keep, but document in CLI help: paths can be zero-hop when entry=crown. Alternatively remove admin from entries — spec says entry nodes are internet-exposed; leave as is, it is evidence-consistent.

REMAINING (Phase 10 + delivery):
1. README.md — overview, evidence model, commands table, exit codes, data sources/attribution (NVD attribution string), install from source.
2. todo.md — mark Phase 2,3,4,5 items complete (items 2.1-2.5 discovery: dns/http/tls/rdap done; 3.1-3.7 vuln pipeline done; 4.x risk engine done; 5.x graph done).
3. go version test: tests/fixtures present (kev.csv). git add -A; first commit "initial implementation: core CLI, discovery, vulnerability intelligence, risk engine, attack graph"; push to RajaMuhammadAwais/RISKX.
4. Deliver final message with summary.
Shell one-liner for env: export PATH=$PATH:/usr/local/go/bin:/home/ubuntu/go/bin
