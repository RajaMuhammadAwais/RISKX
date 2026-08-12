package reporting

import (
	"bytes"
	"encoding/csv"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func TestCSVMultiSectionShapeIsSingleSection(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-08-12T00:00:00Z")
	var b bytes.Buffer
	w := NewCSVWriter(&b)
	_ = w.Scores([]models.RiskScore{{AssetID: "a", Score: 1, Severity: models.SevLow, ModelVersion: "x"}})
	_ = w.Assets([]models.Asset{{ID: "a", Kind: models.KindHost, Value: "v", Exposure: models.ExposureInternal, FirstSeen: now, LastSeen: now}})
	t.Logf("output:\n%s", b.String())
	// A single CSVWriter stream has exactly one record shape. Writing two
	// different sections (scores + assets) into one stream produces rows of
	// different widths; this is a documented limitation of RFC 4180 CSV and
	// the reason consumers needing full evidence should use JSONL or SARIF.
	r := csv.NewReader(&b)
	_, err := r.ReadAll()
	if err == nil {
		t.Fatal("expected multi-shape CSV read to fail (documented limitation)")
	}
}
