package delta

import (
	"testing"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func asset(id, value string, fp models.Fingerprint) models.Asset {
	return models.Asset{ID: id, Kind: models.KindDomain, Value: value,
		Exposure: models.ExposureInternet, Fingerprint: fp, Schema: "asset-v1"}
}

func finding(id, assetID, title string, sev models.Severity) models.Finding {
	return models.Finding{ID: id, AssetID: assetID, Title: title,
		Severity: sev, Schema: "finding-v1"}
}

func TestFirstRunAllNew(t *testing.T) {
	a1 := asset("a1", "sub.example.com", models.Fingerprint{HTTPServer: "nginx/1.25"})
	a2 := asset("a2", "api.example.com", models.Fingerprint{})
	f1 := finding("f1", "a1", "old TLS", models.SevMedium)
	items := Diff(nil, []models.Asset{a1, a2}, []models.Finding{f1}, "run-1")
	if len(items) != 3 {
		t.Fatalf("want 3 items (2 assets + 1 finding), got %d", len(items))
	}
	for _, it := range items {
		if it.CurrentRun != "run-1" || it.PriorRun != "" {
			t.Errorf("first-run item should carry only current run: %+v", it)
		}
	}
	sum := Summary(items)
	if sum[KindNewAsset] != 2 || sum[KindNewFinding] != 1 {
		t.Errorf("unexpected summary: %v", sum)
	}
}

func TestGoneAssetRequiresPriorPersistence(t *testing.T) {
	priorAssets := []models.Asset{
		asset("a1", "sub.example.com", models.Fingerprint{HTTPServer: "nginx/1.25"}),
		asset("a2", "stale.example.com", models.Fingerprint{HTTPServer: "apache/2.4"}),
	}
	priorFindings := []models.Finding{
		finding("f1", "a1", "old TLS", models.SevMedium),
		finding("f2", "a1", "missing header", models.SevLow),
	}
	prior := NewSnapshot("run-0", priorAssets, priorFindings)

	// Second run: a2 is not discovered; f2 is no longer observed.
	items := Diff(&prior,
		[]models.Asset{asset("a1", "sub.example.com", models.Fingerprint{HTTPServer: "nginx/1.25"})},
		[]models.Finding{finding("f1", "a1", "old TLS", models.SevMedium)},
		"run-1")

	sum := Summary(items)
	if sum[KindGoneAsset] != 1 || sum[KindResolvedFinding] != 1 || sum[KindChangedAsset] != 0 || sum[KindChangedFinding] != 0 {
		t.Errorf("unexpected summary: %v", sum)
	}
	for _, it := range items {
		switch it.Kind {
		case KindGoneAsset:
			if it.ID != "a2" || it.Label != "stale.example.com" || it.PriorRun != "run-0" {
				t.Errorf("gone_asset malformed: %+v", it)
			}
		case KindResolvedFinding:
			if it.ID != "f2" || it.PriorRun != "run-0" {
				t.Errorf("resolved_finding malformed: %+v", it)
			}
		default:
			t.Errorf("unexpected kind: %s", it.Kind)
		}
	}
}

func TestChangedAssetFieldLevelDiff(t *testing.T) {
	fpOld := models.Fingerprint{HTTPServer: "nginx/1.25", TLSKeyBits: 2048}
	fpNew := models.Fingerprint{HTTPServer: "nginx/1.27", TLSKeyBits: 4096}
	priorAssets := []models.Asset{asset("a1", "sub.example.com", fpOld)}
	prior := NewSnapshot("run-0", priorAssets, nil)
	items := Diff(&prior, []models.Asset{asset("a1", "sub.example.com", fpNew)}, nil, "run-1")
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	it := items[0]
	if it.Kind != KindChangedAsset {
		t.Fatalf("want changed_asset, got %s", it.Kind)
	}
	if it.PriorRun != "run-0" || it.CurrentRun != "run-1" {
		t.Errorf("run tracking missing: %+v", it)
	}
	// Exactly the two changed fields, nothing else.
	want := map[string]bool{"http_server": true, "tls_key_bits": true}
	if len(it.Changes) != 2 {
		t.Fatalf("want 2 changed fields, got %v", it.Changes)
	}
	for _, c := range it.Changes {
		if !want[c] {
			t.Errorf("unexpected changed field %q", c)
		}
	}
}

func TestUnknownVsUnknownNeverChanges(t *testing.T) {
	// Unobserved (empty) fingerprint fields must never register as changes —
	// that is the core no-guessing invariant: absent evidence ≠ evidence.
	fp := models.Fingerprint{}
	prior := NewSnapshot("run-0", []models.Asset{asset("a1", "x.example.com", fp)}, nil)
	items := Diff(&prior, []models.Asset{asset("a1", "x.example.com", fp)}, nil, "run-1")
	if len(items) != 0 {
		t.Errorf("empty-vs-empty must produce no delta items, got %v", items)
	}
}

func TestFPHashStableAcrossRunsAndOrderInsensitive(t *testing.T) {
	fp := models.Fingerprint{
		TLSSANs: []string{"a.example.com", "z.example.com", "m.example.com"},
		HTTPServer: "caddy/2.7", TLSKeyBits: 4096,
	}
	h1 := fpHash(fp)
	reversed := fp
	reversed.TLSSANs = []string{"z.example.com", "m.example.com", "a.example.com"}
	h2 := fpHash(reversed)
	if h1 != h2 {
		t.Errorf("fpHash order-dependent: %s != %s", h1, h2)
	}
	if h1 == fpHash(models.Fingerprint{HTTPServer: "caddy/2.7"}) {
		t.Errorf("fpHash should differ when SANs differ")
	}
}

func TestGoneAssetNotEmittedForNeverSeenID(t *testing.T) {
	prior := NewSnapshot("run-0", []models.Asset{
		asset("a1", "x.example.com", models.Fingerprint{})}, nil)
	// Input set references only a1; the prior contains nothing about a99 —
	// a99 must NOT appear as gone_asset (no-guessing).
	items := Diff(&prior, []models.Asset{
		asset("a1", "x.example.com", models.Fingerprint{})}, nil, "run-1")
	for _, it := range items {
		if it.Kind == KindGoneAsset && it.ID == "a99" {
			t.Errorf("gone_asset emitted for a never-persisted id: %+v", it)
		}
	}
}

func TestSummaryEmpty(t *testing.T) {
	sum := Summary(nil)
	if len(sum) != 0 {
		t.Errorf("nil items must summarize empty, got %v", sum)
	}
}

func TestFPHashIgnoresUnobservedNilFields(t *testing.T) {
	base := models.Fingerprint{HTTPServer: "nginx/1.25"}
	withNil := base
	// TLSExpired nil vs explicit false must differ (one observed, one not):
	explicitFalse := models.Fingerprint{HTTPServer: "nginx/1.25", TLSExpired: boolPtr(false)}
	if fpHash(base) == fpHash(explicitFalse) {
		t.Errorf("nil vs observed-false should produce different hashes")
	}
	if fpHash(base) != fpHash(withNil) {
		t.Errorf("identical structs must hash identically")
	}
}

func boolPtr(b bool) *bool { return &b }
