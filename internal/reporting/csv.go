package reporting

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// CSVWriter serializes findings, scores, and assets as RFC 4180 CSV (via
// encoding/csv, which handles quoting and escaping per RFC 4180). CSV is a
// flattened projection of the canonical JSON: nested evidence and suppression
// objects are NOT flattened into cell content (documented limitation — a
// flattened CSV row cannot carry a variable-length evidence chain without
// inventing an encoding, which the no-guessing policy forbids). Consumers who
// need full evidence must use JSONL or SARIF.
type CSVWriter struct {
	w *csv.Writer
}

func NewCSVWriter(w io.Writer) *CSVWriter {
	return &CSVWriter{w: csv.NewWriter(w)}
}

const csvTSFmt = "2006-01-02T15:04:05Z07:00"

// Findings writes findings as CSV with active-suppression status evaluated at
// the given reference time.
func (c *CSVWriter) Findings(findings []models.Finding, now time.Time) error {
	if err := c.w.Write([]string{
		"finding_id", "asset_value", "title", "severity", "confidence",
		"status", "validation", "suppression", "references",
	}); err != nil {
		return err
	}
	for _, f := range findings {
		sup := "none"
		if f.Suppression != nil {
			sup = "active"
			if !f.Suppression.IsActive(now) {
				sup = "expired"
			}
		}
		if err := c.w.Write([]string{
			f.ID, f.AssetValue, f.Title, string(f.Severity), string(f.Confidence),
			string(f.Status), string(f.Validation), sup,
			strings.Join(f.References, ";"),
		}); err != nil {
			return err
		}
	}
	c.w.Flush()
	return c.w.Error()
}

// Scores writes risk scores as CSV. Factor/evidence detail is not flattened
// (see package doc); incomplete/stale inputs are listed in-cell.
func (c *CSVWriter) Scores(scores []models.RiskScore) error {
	if err := c.w.Write([]string{
		"asset_id", "score", "severity", "model_version", "stale_inputs",
		"incomplete_inputs",
	}); err != nil {
		return err
	}
	for _, s := range scores {
		if err := c.w.Write([]string{
			s.AssetID, fmt.Sprintf("%.2f", s.Score), string(s.Severity),
			s.ModelVersion, strings.Join(s.Stale, ";"),
			strings.Join(s.Incomplete, ";"),
		}); err != nil {
			return err
		}
	}
	c.w.Flush()
	return c.w.Error()
}

// Assets writes assets as CSV.
func (c *CSVWriter) Assets(assets []models.Asset) error {
	if err := c.w.Write([]string{
		"id", "kind", "value", "host", "port", "exposure", "provenance_confidence",
		"first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, a := range assets {
		if err := c.w.Write([]string{
			a.ID, string(a.Kind), a.Value, a.Host,
			fmt.Sprintf("%d", a.Port), string(a.Exposure),
			string(a.Provenance.Confidence),
			a.FirstSeen.Format(csvTSFmt), a.LastSeen.Format(csvTSFmt),
		}); err != nil {
			return err
		}
	}
	c.w.Flush()
	return c.w.Error()
}
