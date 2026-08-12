// storage package tests: persistence roundtrips pin the evidence store
// contract (Phase 2.6 / v0.2 storage wiring). All tests run against a
// temp-file SQLite database; no external network.
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "riskx.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestSchemaPermissions verifies the store creates its DB with 0600 mode.
func TestSchemaPermissions(t *testing.T) {
	s := newTestStore(t)
	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows ignores permission bits on file creation, so the 0600
	// contract is only assertable on POSIX systems.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("db permissions = %o, want 0600", info.Mode().Perm())
	}
}

// TestSchemaVersion verifies the versioned schema marker.
func TestSchemaVersion(t *testing.T) {
	if SchemaVersion() != "storage-v2" {
		t.Errorf("schema version = %q, want storage-v2", SchemaVersion())
	}
}

// TestAssetsRoundtrip pins the assets insert/list path: idempotent writes
// (re-insert does not duplicate), TEXT time columns roundtrip through
// RFC3339, and provenance/fingerprint JSON survives.
func TestAssetsRoundtrip(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	a := models.Asset{
			ID: "asset-abc", Kind: models.KindHost, Value: "host-1.example.com",
			Host: "host-1.example.com", Port: 443, Protocol: "https",
			Exposure: models.ExposureInternet, Criticality: "high",
			FirstSeen: now, LastSeen: now,
			Provenance:  models.Provenance{Source: "dns", Method: "lookup", Confidence: models.ConfidenceHigh},
			Fingerprint: models.Fingerprint{TLSIssuer: "issuer-1"},
			Schema:      "asset-v1",
		}
	n, err := s.PutAssets([]models.Asset{a})
	if err != nil {
		t.Fatalf("put assets: %v", err)
	}
	if n != 1 {
		t.Errorf("put count = %d, want 1", n)
	}
	// Idempotency: re-insert must not duplicate.
	if _, err := s.PutAssets([]models.Asset{a}); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	got, err := s.ListAssets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("list count = %d, want 1", len(got))
	}
	g := got[0]
	if g.Value != a.Value || g.Port != a.Port || g.Criticality != a.Criticality {
		t.Errorf("asset mismatch: got %+v", g)
	}
	// TEXT→time roundtrip: second precision (RFC3339).
	if g.LastSeen.Sub(now) > time.Second {
		t.Errorf("last_seen roundtrip drifted beyond 1s: %v", g.LastSeen)
	}
}

// TestFindingsRoundtrip pins findings insert/list: severity, confidence,
// classification JSON, remediation pointer, and references survive the
// TEXT column boundary (regression: "references" reserved keyword rename
// to "refs" broke this path in v0.2).
func TestFindingsRoundtrip(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	f := models.Finding{
		ID: "finding-1", AssetID: "asset-abc", AssetValue: "host-1.example.com",
		Title: "Exposed service", Observation: "records=A",
		Severity: models.SevHigh, Confidence: models.ConfidenceHigh,
		Status: "open", Validation: "unvalidated",
		Classification: models.Classification{OWASPTop10: "A01:2025"},
		Remediation:    &models.Remediation{Problem: "exposure"},
		References:     []string{"https://cve.org/CVE-2025-0001"},
		CreatedAt:      now, Schema: "finding-v1",
	}
	if err := s.PutFindings([]models.Finding{f}); err != nil {
		t.Fatalf("put findings: %v", err)
	}
	got, err := s.ListFindings()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("list count = %d, want 1", len(got))
	}
	g := got[0]
	if g.Severity != models.SevHigh || g.Confidence != models.ConfidenceHigh {
		t.Errorf("severity/confidence mismatch: %+v", g)
	}
	if g.Classification.OWASPTop10 != "A01:2025" {
		t.Errorf("classification JSON lost: %v", g.Classification)
	}
	if g.Remediation == nil || g.Remediation.Problem != "exposure" {
		t.Errorf("remediation pointer lost: %v", g.Remediation)
	}
	if len(g.References) != 1 || g.References[0] != "https://cve.org/CVE-2025-0001" {
		t.Errorf("references lost: %v", g.References)
	}
}

// TestRiskScoreUpsert pins the score upsert and list path, including the
// stale/incomplete inputs JSON arrays.
func TestRiskScoreUpsert(t *testing.T) {
	s := newTestStore(t)
	sc := models.RiskScore{
		AssetID: "asset-abc", Score: 72.5, Severity: models.SevHigh,
		Factors:      []models.RiskFactor{{Name: "exposure", Value: 30, Evidence: []models.Evidence{{Type: "discovery", Source: "dns", Value: "A 1.2.3.4", Citation: models.SourceCitation{Organization: "IETF", Document: "RFC 1035", URL: "https://www.rfc-editor.org/rfc/rfc1035"}}}}},
		Weights:      map[string]float64{"exposure": 0.3},
		ModelVersion: "risk-v1",
		Stale:        []string{"kev feed 3 days old"},
		Incomplete:   []string{"no IAM data"},
	}
	if err := s.PutRiskScore(sc); err != nil {
		t.Fatalf("put score: %v", err)
	}
	got, err := s.ListRiskScores()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Score != 72.5 {
		t.Fatalf("score mismatch: %v", got)
	}
	if len(got[0].Stale) != 1 || got[0].Stale[0] != "kev feed 3 days old" {
		t.Errorf("stale inputs lost: %v", got[0].Stale)
	}
	// Upsert updates score without duplicating.
	sc.Score = 80
	if err := s.PutRiskScore(sc); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ = s.ListRiskScores()
	if len(got) != 1 || got[0].Score != 80 {
		t.Errorf("upsert failed: %v", got)
	}
}

// TestCount verifies the summary count query over the three primary tables.
func TestCount(t *testing.T) {
	s := newTestStore(t)
	a, f, r, err := s.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if a != 0 || f != 0 || r != 0 {
		t.Errorf("initial counts = %d/%d/%d, want 0/0/0", a, f, r)
	}
	_, _ = s.PutAssets([]models.Asset{{ID: "x", Kind: models.KindHost, Value: "h", Exposure: models.ExposureInternet, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Provenance: models.Provenance{}, Fingerprint: models.Fingerprint{}, Schema: "asset-v1"}})
	a2, f2, r2, err := s.Count()
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if a2 != 1 || f2 != 0 || r2 != 0 {
		t.Errorf("after insert counts = %d/%d/%d, want 1/0/0", a2, f2, r2)
	}
}

// TestDeltaSnapshotRoundtrip pins the delta-v1 snapshot persistence path:
// write, idempotent re-insert, load by ID, and ordering of snapshot IDs.
func TestDeltaSnapshotRoundtrip(t *testing.T) {
	s := newTestStore(t)
	p1 := json.RawMessage(`{"id":"snap-1","schema":"delta-v1"}`)
	p2 := json.RawMessage(`{"id":"snap-2","schema":"delta-v1"}`)
	t1 := time.Date(2026, 8, 12, 0, 0, 1, 0, time.UTC)
	t2 := time.Date(2026, 8, 12, 0, 0, 2, 0, time.UTC)
	if err := s.PutDeltaSnapshot("snap-1", p1, t1); err != nil {
		t.Fatalf("put snap-1: %v", err)
	}
	// Idempotency: re-inserting with the same ID must not fail.
	if err := s.PutDeltaSnapshot("snap-1", p1, t1); err != nil {
		t.Fatalf("re-insert snap-1: %v", err)
	}
	if err := s.PutDeltaSnapshot("snap-2", p2, t2); err != nil {
		t.Fatalf("put snap-2: %v", err)
	}
	ids, err := s.ListDeltaSnapshotIDs()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 2 || ids[0] != "snap-1" || ids[1] != "snap-2" {
		t.Errorf("ids = %v, want [snap-1 snap-2]", ids)
	}
	got, err := s.DeltaSnapshotPayload("snap-2")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if string(got) != string(p2) {
		t.Errorf("payload = %q, want %q", got, p2)
	}
	// Missing snapshot must not be an error (no prior snapshot = first run).
	none, err := s.DeltaSnapshotPayload("snap-missing")
	if err != nil {
		t.Fatalf("payload missing: %v", err)
	}
	if none != nil {
		t.Errorf("missing snapshot must return nil, got %q", none)
	}
}
