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

## V0.2 REQUEST (2026-08-12, after v0.1 delivery)
User: "continue next version research based also add cicd etc". v0.1 (commit c60027e) pushed to RajaMuhammadAwais/RISKX with Phases 1-5 + todo Q items partially done (README done; CI workflow Q.2 NOT done; benchmarks.md Q.4 NOT done; Q.5 NOT done).

V0.2 scope decided (spec/roadmap-consistent):
1. Phase 6 reporting/export: riskx report summary (real findings from storage + vuln/risk data), JSONL+CSV export (6.2), --suppress/exception support (6.4). SARIF: primary-source verify SARIF 2.1.0 schema + evaluation, implement exporter plugin stub if verified.
2. Storage persistence (2.6/6 integration): SQLite asset+finding store via internal/storage/storage.go (already has DB scaffold? check internal/storage/storage.go) — wire discover/vuln/risk to store.
3. CI/CD: GitHub Actions workflows — go test -race, go vet, staticcheck, golangci-lint (pin go version per .golangci.yml), dependency-audit (govulncheck), release build matrix (linux/amd64, darwin/amd64, windows/amd64), go mod tidy check.
4. Phase 7 start (AWS candidate per ADR-0007): passive AWS asset discovery — no-credential enumeration is not possible; implement cloud discovery framework with AWS STS whoami / AWS resource listing via readonly IAM (access key env vars) gated by mode; defer heavy bits, mark scope.
5. Validate command: real safe validation workflow (DNS record check, TLS cert check, HTTP probe) with plan print + authorization.
6. Benchmarks.md (Q.4) with recorded results.
7. Update research docs + README version, tag v0.2.0, push.

Existing key facts: repo at /home/ubuntu/RISKX, go at /usr/local/go/bin (1.26), env: export PATH=$PATH:/usr/local/go/bin:/home/ubuntu/go/bin. Tests: CGO_ENABLED=1 go test ./... -race -count=1. staticcheck in ~/go/bin. KEV embed: internal/vulnerability/ingest/kev_snapshot.csv. Feed skip env: RISKX_SKIP_FEEDS.
cmd_analysis.go report/export/policy/validate currently stubs (report summary returns JSON stub; export jsonl/csv stubs; policy check stub w/ fFile; validate has mode+auth wiring already using safe actions).
internal/storage/storage.go exists (SQLite assets/findings/evidence, 0600). Must check its API before wiring.

## V0.2 RESEARCH + PLAN (2026-08-12)
RESEARCH DONE (all verified against primary sources, see docs/research/v0.2-reporting-cicd-cloud.md):
- SARIF 2.1.0 = OASIS Standard + Errata 01 (2023-08-28). Spec + errata01 schema downloaded to docs/research/schemas/sarif-schema-2.1.0.json (official). version string "2.1.0"; log{version,runs[]}; run{tool{driver{name}},results[]}; result{ruleId,level("none"|"note"|"warning"|"error"),message{text}}; properties extension point valid; region requires startLine/charOffset/byteOffset. Errata #481: runs must not be null.
- CI versions verified: actions/checkout@v6, setup-go@v7 (go-version-file), golangci/golangci-lint-action@v9 (needs golangci-lint v2.x; pin version: v2.1.6), staticcheck-action@v1 (install-go:false), golang/govulncheck-action@v1.
- AWS APIs verified from docs.aws.amazon.com: STS GetCallerIdentity (POST form Action+Version=2011-06-15, host sts.amazonaws.com, no perms needed, XML Arn/UserId/Account); EC2 DescribeInstances (GET, ec2.{region}.amazonaws.com, Version=2016-11-15, MaxResults+NextToken pagination recommended); S3 ListBuckets (GET https://s3.amazonaws.com/, s3:ListAllMyBuckets, XML Name/CreationDate/BucketRegion/BucketArn); IAM ListUsers (GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08, IsTruncated/Marker pagination MaxItems default 100 max 1000). All query APIs → SigV4 with empty payload.
DECISIONS: minimal dependency-free SigV4 (empty payload, signed headers host;x-amz-date); creds env-only AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_REGION (default us-east-1), never profiles/shared creds; `riskx cloud aws whoami|instances|buckets|identities|all`; mode safe+ required; creds redacted.
IMPLEMENTATION PLAN in docs/research/_v02_plan.md (full detail incl. SigV4 test vectors + model API facts). ADR-0008.md written (storage wiring). todo.md updated (Phases 2-5 marked complete; v0.2 items added).
NEXT: implement in this order: (1) internal/reporting (summary/jsonl/csv/sarif + tests w/ schema validation), (2) storage.go ListEvidence add + cmd wiring (helpers.go openStore, cmd_discovery.go discover/vuln/risk/assets, cmd_analysis.go report summary/export/validate), (3) internal/validate (DNS/TLS/HTTP read-only checks), (4) internal/cloud/aws (SigV4 + query client + fixtures), (5) CI workflows + .golangci.yml, (6) benchmarks.md + README update, (7) test/lint/bench/commit/push tag v0.2.0.
Note: reporting pkg currently empty dir. cloud pkg empty dir. storage schemaVersion "storage-v1".

## V0.2 IMPLEMENTATION COMPLETE (2026-08-12)
All 15 test packages pass with race detector (added internal/storage regression suite: permissions, schema version, assets/findings/riskscores roundtrip, count). Staticcheck ./... clean.
Bugs fixed during smoke test: (1) storeClose() called BEFORE use in discover/vuln/validate persistence blocks — moved AFTER use. (2) findings SQL column "references" clashes with SQLite reserved keyword — renamed to "refs" in schema + PutFindings + ListFindings. (3) ListAssets/ListFindings scanned TEXT time cols into time.Time — fixed with sql.NullString + RFC3339 parse. (4) dnsResult auto-passed empty records for existence checks — fixed: empty records never pass. (5) staticcheck: validate self-assignment removed; unused futureSections → populated in Summary.Counts; staticResolver wired via Resolver.static/LookupTable + lookupStatic(ctx) — used by new TestVerifyDNSStaticResolver.
v0.2 feature set shipped:
- internal/reporting: summary JSON (w/ future_sections listing deferred report sections), JSONL, CSV (RFC 4180), SARIF 2.1.0 exporter (validated against official OASIS errata01 schema in tests).
- CLI: riskx report summary; riskx export jsonl|csv|sarif --data; riskx cloud discover (whoami/instances/buckets/identities/all, SigV4 cross-verified vs botocore reference signer); riskx validate (real DNS/TLS/HTTP checks w/ authorization gating).
- Persistence: discover/vuln/risk/validate/cloud write to SQLite (--data/RISKX_DATA); assets list reads store; risk falls back to documented demo input when no store.
- CI: .github/workflows/{ci,lint,staticcheck,vuln}.yml (Go 1.25, setup-go@v7, golangci-lint-action@v9 v2.1.6, staticcheck-action@v1, govulncheck-action@v1). go.mod=1.25.0 (modernc.org/libc requires 1.25).
- E2E verified: discover github.com → 14 assets; vuln CVE-2021-44228 CVE-2024-3094 → 2 critical findings persisted; risk score max 20; report summary counts match; SARIF export validates (2 results).
REMAINING: benchmarks.md update, README update (v0.2.0 + CI table), commit+push v0.2.0, tag v0.2.0, deliver.
