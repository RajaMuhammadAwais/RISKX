package reporting

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func timeMust(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func sampleFindings() []models.Finding {
	return []models.Finding{
		{
			ID:         "RISKX-abc123",
			Schema:     models.SchemaFinding,
			AssetID:    "asset-web",
			AssetValue: "web.example.com",
			Title:      "CVE-2021-44228 log4j remote code execution",
			Observation: "CVE-2021-44228 reported for web.example.com",
			Severity:   models.SevCritical,
			Confidence: models.ConfidenceHigh,
			Status:     models.StatusObserved,
			Validation: models.ValidationUnvalidated,
			References: []string{"CVE-2021-44228"},
			CreatedAt:  timeMust("2026-08-12T00:00:00Z"),
		},
		{
			ID:         "RISKX-def456",
			Schema:     models.SchemaFinding,
			AssetID:    "asset-db",
			AssetValue: "db.internal",
			Title:      "Medium severity web finding",
			Observation: "medium observation",
			Severity:   models.SevMedium,
			Confidence: models.ConfidenceMedium,
			Status:     models.StatusInferred,
			Validation: models.ValidationUnvalidated,
			CreatedAt:  timeMust("2026-08-12T00:00:00Z"),
		},
		{
			ID:         "RISKX-sup1",
			Schema:     models.SchemaFinding,
			AssetValue: "suppressed.example.com",
			Title:      "Suppressed low finding",
			Severity:   models.SevLow,
			Confidence: models.ConfidenceLow,
			Status:     models.StatusObserved,
			Validation: models.ValidationUnvalidated,
			Suppression: &models.Suppression{
				Reason: "accepted risk", Owner: "team-lead",
				CreatedAt: timeMust("2026-08-01T00:00:00Z"),
				ExpiresAt: timeMust("2027-08-01T00:00:00Z"),
			},
			CreatedAt: timeMust("2026-08-12T00:00:00Z"),
		},
		{
			ID:         "RISKX-exp1",
			Schema:     models.SchemaFinding,
			AssetValue: "expired.example.com",
			Title:      "Expired suppression must resurface",
			Severity:   models.SevHigh,
			Confidence: models.ConfidenceMedium,
			Status:     models.StatusObserved,
			Validation: models.ValidationUnvalidated,
			Suppression: &models.Suppression{
				Reason: "temporary", Owner: "ops",
				CreatedAt: timeMust("2026-01-01T00:00:00Z"),
				ExpiresAt: timeMust("2026-02-01T00:00:00Z"),
				Expired:   true,
			},
			CreatedAt: timeMust("2026-08-12T00:00:00Z"),
		},
	}
}

func sampleScores() []models.RiskScore {
	return []models.RiskScore{
		{
			AssetID:      "asset-web",
			Score:        82.5,
			Severity:     models.SevCritical,
			ModelVersion: "risk-v1",
			Stale:        []string{"epss"},
			Incomplete:   []string{"centrality"},
		},
		{
			AssetID:      "asset-db",
			Score:        45.0,
			Severity:     models.SevMedium,
			ModelVersion: "risk-v1",
		},
	}
}

func sampleAssets() []models.Asset {
	now := timeMust("2026-08-12T00:00:00Z")
	return []models.Asset{
		{
			ID: "asset-web", Kind: models.KindHost, Value: "web.example.com",
			Exposure: models.ExposureInternet, FirstSeen: now, LastSeen: now,
			Provenance: models.Provenance{Source: "dns", Confidence: models.ConfidenceHigh},
		},
	}
}

func TestSummaryCounts(t *testing.T) {
	in := SummaryInput{Assets: sampleAssets(), Findings: sampleFindings(), Scores: sampleScores()}
	sum := Summary(in)
	if sum.Counts.Assets != 1 {
		t.Errorf("assets count: got %d, want 1", sum.Counts.Assets)
	}
	if sum.Counts.Findings != 4 {
		t.Errorf("findings count: got %d, want 4", sum.Counts.Findings)
	}
	if sum.Counts.CriticalFindings != 1 {
		t.Errorf("critical: got %d, want 1", sum.Counts.CriticalFindings)
	}
	if sum.Counts.HighFindings != 1 {
		t.Errorf("high: got %d, want 1", sum.Counts.HighFindings)
	}
	// Suppressed low finding excluded from critical/high counts; expired
	// suppression re-exposes the high finding (counts as high).
	if sum.Counts.ActiveSuppressions != 1 {
		t.Errorf("active suppressions: got %d, want 1", sum.Counts.ActiveSuppressions)
	}
	if sum.Counts.SuppressedFindings != 1 {
		t.Errorf("suppressed findings: got %d, want 1", sum.Counts.SuppressedFindings)
	}
	if sum.Counts.AverageRiskScore != 63.75 {
		t.Errorf("avg score: got %.2f, want 63.75", sum.Counts.AverageRiskScore)
	}
	if sum.Counts.MaxRiskScore != 82.5 {
		t.Errorf("max score: got %.2f, want 82.5", sum.Counts.MaxRiskScore)
	}
	if len(sum.Sections) != 6 {
		t.Errorf("sections: got %d, want 6", len(sum.Sections))
	}
	// Affected assets ordered by descending score.
	affected := ""
	for _, s := range sum.Sections {
		if s.Title == "Affected assets" {
			affected = s.Content
		}
	}
	webIdx := strings.Index(affected, "asset-web")
	dbIdx := strings.Index(affected, "asset-db")
	if webIdx < 0 || dbIdx < 0 || webIdx > dbIdx {
		t.Errorf("affected assets not ordered descending by score:\n%s", affected)
	}
}

func TestSummaryEmptyInputs(t *testing.T) {
	sum := Summary(SummaryInput{})
	if sum.Counts.Findings != 0 || sum.Counts.Assets != 0 {
		t.Errorf("empty input counts nonzero: %+v", sum.Counts)
	}
	for _, s := range sum.Sections {
		switch s.Title {
		case "Risk overview":
			if !strings.Contains(s.Content, "No risk scores are stored yet") {
				t.Errorf("missing no-scores note: %s", s.Content)
			}
		case "Critical exposures":
			if !strings.Contains(s.Content, "No critical exposures recorded") && !strings.Contains(s.Content, "No critical-severity findings") {
				t.Errorf("missing no-critical note: %s", s.Content)
			}
		}
	}
}

func TestHumanReportContainsAttribution(t *testing.T) {
	sum := Summary(SummaryInput{Findings: sampleFindings(), Scores: sampleScores()})
	h := HumanReport(sum)
	if !strings.Contains(h, "NVD") {
		t.Error("human report missing NVD attribution")
	}
	if !strings.Contains(h, "reporting-v1") {
		t.Error("human report missing model version")
	}
}

func TestJSONLRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONLWriter(&buf)
	if err := w.Write(JSONLOptions{Findings: sampleFindings(), Scores: sampleScores(), Assets: sampleAssets()}); err != nil {
		t.Fatalf("write: %v", err)
	}
	hdr, recs, err := ParseJSONL(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := 4 + 2 + 1
	if hdr.RecordCount != want {
		t.Errorf("record count: got %d, want %d", hdr.RecordCount, want)
	}
	if len(recs) != want {
		t.Fatalf("records: got %d, want %d", len(recs), want)
	}
	// First 4 records are findings, verify one decodes back.
	var f models.Finding
	if err := json.Unmarshal(recs[0], &f); err != nil {
		t.Fatalf("decode finding: %v", err)
	}
	if f.ID != "RISKX-abc123" || f.Severity != models.SevCritical {
		t.Errorf("decoded finding mismatch: %+v", f)
	}
	var s models.RiskScore
	if err := json.Unmarshal(recs[4], &s); err != nil {
		t.Fatalf("decode score: %v", err)
	}
	if s.AssetID != "asset-web" || s.Score != 82.5 {
		t.Errorf("decoded score mismatch: %+v", s)
	}
	var a models.Asset
	if err := json.Unmarshal(recs[6], &a); err != nil {
		t.Fatalf("decode asset: %v", err)
	}
	if a.Kind != models.KindHost {
		t.Errorf("decoded asset mismatch: %+v", a)
	}
	// Every line independently parses (JSONL contract).
	for i, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var raw json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestCSVFindingsRFC4180(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSVWriter(&buf)
	now := timeMust("2026-08-12T00:00:00Z")
	if err := w.Findings(sampleFindings(), now); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("RFC 4180 read: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("rows: got %d, want 5 (header + 4 findings)", len(rows))
	}
	if rows[0][0] != "finding_id" {
		t.Errorf("header mismatch: %v", rows[0])
	}
	// The suppressed finding's suppression column must say active,
	// the expired one must say expired, unsuppressed ones say none.
	sup := map[string]string{}
	for _, row := range rows[1:] {
		sup[row[0]] = row[7]
	}
	if sup["RISKX-sup1"] != "active" {
		t.Errorf("sup1 suppression: got %q, want active", sup["RISKX-sup1"])
	}
	if sup["RISKX-exp1"] != "expired" {
		t.Errorf("exp1 suppression: got %q, want expired", sup["RISKX-exp1"])
	}
	if sup["RISKX-abc123"] != "none" {
		t.Errorf("abc123 suppression: got %q, want none", sup["RISKX-abc123"])
	}
}

func TestCSVScoresAndAssets(t *testing.T) {
	var scoresBuf, assetsBuf bytes.Buffer
	sw := NewCSVWriter(&scoresBuf)
	if err := sw.Scores(sampleScores()); err != nil {
		t.Fatalf("scores: %v", err)
	}
	aw := NewCSVWriter(&assetsBuf)
	if err := aw.Assets(sampleAssets()); err != nil {
		t.Fatalf("assets: %v", err)
	}
	// Each section is its own RFC 4180 record shape (documented CSV
	// limitation: one writer, one shape). Validate both sections separately.
	for _, tc := range []struct {
		name string
		buf  *bytes.Buffer
		rows int
	}{
		{"scores", &scoresBuf, 3}, // header + 2 scores
		{"assets", &assetsBuf, 2}, // header + 1 asset
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := csv.NewReader(tc.buf)
			rows, err := r.ReadAll()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if len(rows) != tc.rows {
				t.Fatalf("rows: got %d, want %d", len(rows), tc.rows)
			}
		})
	}
	scoresBuf2 := new(bytes.Buffer)
	sw2 := NewCSVWriter(scoresBuf2)
	_ = sw2.Scores(sampleScores())
	sr := csv.NewReader(scoresBuf2)
	srows, _ := sr.ReadAll()
	if srows[1][0] != "asset-web" {
		t.Errorf("score asset id: got %q", srows[1][0])
	}
	if srows[1][1] != "82.50" {
		t.Errorf("score value: got %q", srows[1][1])
	}
	if srows[1][4] != "epss" {
		t.Errorf("stale input missing: %v", srows[1])
	}
}
