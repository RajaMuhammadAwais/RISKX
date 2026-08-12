package prioritize

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/feed"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// newCache returns an empty feed cache. Feed entries are hand-built so the
// ranking logic can be tested without any network access (no-guessing: tests
// assert exact tier/signal semantics on documented data, not live feeds).
func newCache(t *testing.T) *feed.Cache {
	t.Helper()
	c, err := feed.Open(t.TempDir() + "/cache.json")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func findRank(ranks []FindingRank, id string) *FindingRank {
	for i := range ranks {
		if ranks[i].Finding.ID == id {
			return &ranks[i]
		}
	}
	return nil
}

func TestKEVFindingsRankFirst(t *testing.T) {
	c := newCache(t)
	// A hand-written KEV catalog row mirroring the CISA KEV CSV schema.
	kevValue, _ := json.Marshal(map[string]any{
		"vendor_project": "Microsoft", "product": "Windows",
		"date_added": "2025-01-01", "known_ransomware_use": "Known",
	})
	c.AddTestEntry(feed.Entry{
		Source: "cisa_kev", SourceID: "CVE-2025-1001", Value: string(kevValue),
		Fetched: time.Now().UTC(),
	})
	epssValue, _ := json.Marshal(map[string]any{"epss": 0.75, "percentile": 0.9})
	c.AddTestEntry(feed.Entry{
		Source: "first_epss", SourceID: "CVE-2025-1002", Value: string(epssValue),
		Fetched: time.Now().UTC(),
	})

	findings := []models.Finding{
		{ID: "F2", AssetID: "a1", Severity: models.SevHigh, References: []string{"CVE-2025-1002"}},
		{ID: "F1", AssetID: "a2", Severity: models.SevMedium, References: []string{"CVE-2025-1001"}},
	}
	ranks := Rank(findings, c)

	r1, r2 := findRank(ranks, "F1"), findRank(ranks, "F2")
	if r1 == nil || r2 == nil {
		t.Fatal("findings missing from ranking")
	}
	if r1.Rank != 1 {
		t.Errorf("KEV member must rank first, got rank %d", r1.Rank)
	}
	if r1.Tier != "actively_exploited" {
		t.Errorf("KEV tier = %q, want actively_exploited", r1.Tier)
	}
	if r1.KEV == nil || !r1.KEV.InKEV || r1.KEV.Vendor != "Microsoft" {
		t.Errorf("KEV signal not attached: %+v", r1.KEV)
	}
	if r2.Tier != "high_probability" || r2.EPSS == nil || r2.EPSS.Score != 0.75 {
		t.Errorf("EPSS rank wrong: tier=%q score=%v", r2.Tier, r2.EPSS)
	}
}

func TestNoEvidenceRankedLast(t *testing.T) {
	c := newCache(t)
	findings := []models.Finding{
		{ID: "F1", AssetID: "a1", Severity: models.SevCritical, References: []string{"CVE-2025-9999"}},
		{ID: "F2", AssetID: "a2", Severity: models.SevLow, References: []string{"https://example.com/vendor-advisory"}},
	}
	ranks := Rank(findings, c)
	if ranks[0].Tier != "no_exploit_evidence" {
		t.Errorf("finding with no public exploit evidence must not be promoted: tier %q", ranks[0].Tier)
	}
	if len(ranks[1].Signals) != 0 {
		t.Errorf("non-CVE reference must not be treated as exploit evidence: signals %d", len(ranks[1].Signals))
	}
}

func TestRankDeterministic(t *testing.T) {
	c := newCache(t)
	findings := []models.Finding{
		{ID: "B", AssetID: "a1", Severity: models.SevHigh},
		{ID: "A", AssetID: "a2", Severity: models.SevHigh},
	}
	a := Rank(findings, c)
	b := Rank(findings, c)
	if a[0].Finding.ID != b[0].Finding.ID || a[1].Finding.ID != b[1].Finding.ID {
		t.Error("ranking must be deterministic across identical inputs")
	}
	if a[0].Finding.ID != "A" {
		t.Errorf("tie broken lexicographically: got %q", a[0].Finding.ID)
	}
}

func TestStalenessTravels(t *testing.T) {
	c := newCache(t)
	kevValue, _ := json.Marshal(map[string]any{"vendor_project": "V", "product": "P"})
	c.AddTestEntry(feed.Entry{
		Source: "cisa_kev", SourceID: "CVE-2025-1001", Value: string(kevValue),
		Fetched: time.Now().UTC().Add(-8 * 24 * time.Hour), // older than FeedFreshAge
	})
	findings := []models.Finding{
		{ID: "F1", AssetID: "a1", Severity: models.SevHigh, References: []string{"CVE-2025-1001"}},
	}
	ranks := Rank(findings, c)
	if ranks[0].KEV == nil || !ranks[0].KEV.Stale {
		t.Error("stale cached KEV evidence must be flagged stale in the rank")
	}
}

func TestHasCVEs(t *testing.T) {
	if HasCVEs(nil) {
		t.Error("nil findings must report no CVEs")
	}
	if HasCVEs([]models.Finding{{ID: "F1"}}) {
		t.Error("no references must report no CVEs")
	}
	if !HasCVEs([]models.Finding{{ID: "F1", References: []string{"cve-2025-1001"}}}) {
		t.Error("case-insensitive CVE refs must be recognized")
	}
}
