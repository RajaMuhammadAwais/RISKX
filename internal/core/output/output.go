// Package output renders RISKX results in human-readable and JSON forms.
//
// Both renderers consume the same canonical structures (models.ScanMetadata +
// payload), guaranteeing machine-readable output is never a lossy subset of
// human output. The NVD attribution string is appended automatically whenever
// NVD-sourced data is present (spec §11, licensing research).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// NVDAttribution is required when outputs contain NVD API data.
const NVDAttribution = "This product uses the NVD API but is not endorsed or certified by the NVD."

// Result wraps any command payload with scan metadata for emission.
type Result struct {
	Meta     models.ScanMetadata `json:"meta" yaml:"meta"`
	Payload  any                 `json:"payload" yaml:"payload"`
	Warnings []string            `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// Printer writes Results in the configured format.
type Printer struct {
	out io.Writer
	_   struct{}
}

// NewPrinter builds a printer for the given writer.
func NewPrinter(out io.Writer) *Printer { return &Printer{out: out} }

// EmitJSON writes the result as canonical JSON with 2-space indentation.
func (p *Printer) EmitJSON(r Result) error {
	enc := json.NewEncoder(p.out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// HumanSummary renders a stable human-readable header, warnings, and a note
// footer. Specific commands format their own payloads via Renderers.
func (p *Printer) HumanSummary(r Result) error {
	w := p.out
	fmt.Fprintf(w, "RISKX %s | risk model %s | mode %s\n",
		r.Meta.ToolVersion, r.Meta.RiskModel, r.Meta.Mode)
	if len(r.Meta.Feeds) > 0 {
		fmt.Fprintln(w, "Feed status:")
		for _, f := range r.Meta.Feeds {
			status := "ok"
			if f.Stale {
				status = "STALE"
			}
			if f.Visibility == "incomplete" {
				status = "VISIBILITY INCOMPLETE"
			}
			fmt.Fprintf(w, "  %-12s %s (fetched %s)\n", f.Feed, status, f.LastFetch.Format("2006-01-02 15:04"))
		}
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "WARNING: %s\n", warn)
	}
	for _, attr := range r.Meta.Attribution {
		fmt.Fprintf(w, "NOTE: %s\n", attr)
	}
	return nil
}

// UsesNVD reports whether the result's payload references NVD-sourced data,
// prompting attribution injection. This is a conservative static check over
// the metadata feeds; the vuln pipeline sets it explicitly.
func UsesNVD(r *Result) bool {
	for _, f := range r.Meta.Feeds {
		if strings.EqualFold(f.Feed, "nvd") {
			return true
		}
	}
	for _, a := range r.Meta.Attribution {
		if strings.Contains(a, "NVD API") {
			return true
		}
	}
	return false
}

// AddNVDAttribution appends the required attribution if not already present.
func AddNVDAttribution(m *models.ScanMetadata) {
	if !UsesNVD(&Result{Meta: *m}) {
		return
	}
	for _, a := range m.Attribution {
		if a == NVDAttribution {
			return
		}
	}
	m.Attribution = append(m.Attribution, NVDAttribution)
}

// NewMeta builds ScanMetadata with tool identity and schema versions (spec §45).
func NewMeta(mode string) models.ScanMetadata {
	return models.ScanMetadata{
		Tool:          "riskx",
		ToolVersion:   config.ToolVersion,
		RiskModel:     "risk-v1",
		AssetSchema:   models.SchemaAsset,
		FindingSchema: models.SchemaFinding,
		EvidenceSchema: models.SchemaEvidence,
		Mode:          mode,
	}
}
