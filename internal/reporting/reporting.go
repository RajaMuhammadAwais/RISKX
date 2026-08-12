// Package reporting renders evidence-based risk reports for RISKX findings,
// risk scores, and assets. It implements reporting-v1 and consumes the
// canonical model types (models.Finding, models.RiskScore, models.Asset) so
// human and machine outputs stay consistent (spec §31, §38).
//
// Model version: reporting-v1.
package reporting

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// ModelVersion is the reporting model version carried in all outputs.
const ModelVersion = "reporting-v1"

// SchemaReport is the canonical schema identifier for report documents.
const SchemaReport = "report-v1"

// SummaryInput is the evidence-backed input for a report summary.
type SummaryInput struct {
	Assets   []models.Asset   `json:"assets"`
	Findings []models.Finding `json:"findings"`
	Scores   []models.RiskScore `json:"scores"`
}

// Section is one titled section of the executive report.
type Section struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

// JSONSummary is the canonical machine representation of an executive summary.
type JSONSummary struct {
	Schema      string    `json:"schema"`
	Model       string    `json:"model_version"`
	GeneratedAt time.Time `json:"generated_at"`
	Sections    []Section `json:"sections"`
	Counts      CountSummary `json:"counts"`
}

// CountSummary aggregates report-wide counts.
type CountSummary struct {
	Assets            int            `json:"assets"`
	Findings          int            `json:"findings"`
	CriticalFindings  int            `json:"critical_findings"`
	HighFindings      int            `json:"high_findings"`
	ActiveSuppressions int           `json:"active_suppressions"`
	SuppressedFindings int           `json:"suppressed_findings"`
	AverageRiskScore  float64        `json:"average_risk_score,omitempty"`
	MaxRiskScore      float64        `json:"max_risk_score,omitempty"`
	FutureSections    []string       `json:"future_sections,omitempty"` // deferred per spec
}

var futureSections = []string{
	"attack path analysis",
	"identity posture",
	"cloud posture",
	"AI agent posture",
	"MCP posture",
}

// Summary builds the executive risk summary over stored, evidence-backed data.
func Summary(in SummaryInput) JSONSummary {
	now := time.Now().UTC()
	counts := CountSummary{
		Assets:         len(in.Assets),
		Findings:       len(in.Findings),
		FutureSections: futureSections, // deferred report sections, surfaced per spec
	}
	var crit, high []models.Finding
	for i := range in.Findings {
		f := in.Findings[i]
		if f.Suppression != nil && f.Suppression.IsActive(now) {
			counts.ActiveSuppressions++
			counts.SuppressedFindings++
			continue
		}
		switch f.Severity {
		case models.SevCritical:
			crit = append(crit, f)
			counts.CriticalFindings++
		case models.SevHigh:
			high = append(high, f)
			counts.HighFindings++
		}
	}
	if len(in.Scores) > 0 {
		var total float64
		for _, s := range in.Scores {
			total += s.Score
			if s.Score > counts.MaxRiskScore {
				counts.MaxRiskScore = s.Score
			}
		}
		counts.AverageRiskScore = round2(total / float64(len(in.Scores)))
	}

	// Executive summary: factual, evidence-quantified, no marketing language.
	sections := []Section{
		{
			Title:   "Executive summary",
			Content: fmt.Sprintf("This report covers %d discovered asset(s) and %d finding(s) recorded in the local evidence store (%s, %s). %d critical and %d high findings are open after applying active suppressions.",
				counts.Assets, counts.Findings, ModelVersion, SchemaReport,
				counts.CriticalFindings, counts.HighFindings),
		},
		{
			Title: "Risk overview",
			Content: fmt.Sprintf("Average risk-v1 score across %d scored asset(s): %.2f/100 (max %.2f). Scores are deterministic (model version risk-v1); missing evidence caps factors at zero and is listed in incomplete_inputs per score — nothing is guessed.",
				len(in.Scores), counts.AverageRiskScore, counts.MaxRiskScore),
		},
		criticalSection(crit, now),
		affectedSection(in.Assets, in.Scores),
		evidenceSection(in.Findings),
		remediationSection(crit, high),
	}
	if len(in.Scores) == 0 {
		sections[1] = Section{
			Title:   "Risk overview",
			Content: "No risk scores are stored yet. Run 'riskx risk' after discovery to compute risk-v1 scores over the stored assets. Until then visibility into scoring is incomplete (spec §48); this report does not estimate scores.",
		}
	}
	if counts.Findings == 0 {
		sections[2] = Section{
			Title:   "Critical exposures",
			Content: "No critical exposures recorded in the evidence store. Absence of findings reflects the run's observation scope, not proof of a clean posture.",
		}
		sections[4] = Section{
			Title:   "Remediation guidance",
			Content: "No open high or critical findings to prioritize in this report.",
		}
	}
	return JSONSummary{
		Schema:      SchemaReport,
		Model:       ModelVersion,
		GeneratedAt: now,
		Sections:    sections,
		Counts:      counts,
	}
}

func criticalSection(crit []models.Finding, now time.Time) Section {
	if len(crit) == 0 {
		return Section{
			Title:   "Critical exposures",
			Content: "No critical-severity findings are open.",
		}
	}
	var lines []string
	for _, f := range crit {
		exp := ""
		if f.Suppression != nil && f.Suppression.IsActive(now) {
			exp = " [suppressed until " + f.Suppression.ExpiresAt.Format(time.RFC3339) + "]"
		}
		lines = append(lines, fmt.Sprintf("- %s: %s (asset %s, confidence=%s, validation=%s)%s",
			f.ID, f.Title, f.AssetValue, f.Confidence, f.Validation, exp))
	}
	return Section{Title: "Critical exposures", Content: strings.Join(lines, "\n")}
}

func affectedSection(assets []models.Asset, scores []models.RiskScore) Section {
	if len(scores) == 0 {
		return Section{
			Title:   "Affected assets",
			Content: "No scored assets to rank. Run 'riskx risk' to score stored assets.",
		}
	}
	sorted := make([]models.RiskScore, len(scores))
	copy(sorted, scores)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		return sorted[i].AssetID < sorted[j].AssetID
	})
	var lines []string
	lines = append(lines, "Top scored assets (descending risk-v1 score, model version risk-v1):")
	limit := len(sorted)
	if limit > 10 {
		limit = 10
	}
	for _, s := range sorted[:limit] {
		lines = append(lines, fmt.Sprintf("- %s: %.2f (%s) stale=%d incomplete=%d",
			s.AssetID, s.Score, s.Severity, len(s.Stale), len(s.Incomplete)))
	}
	return Section{Title: "Affected assets", Content: strings.Join(lines, "\n")}
}

func evidenceSection(findings []models.Finding) Section {
	var count int
	for _, f := range findings {
		count += len(f.Evidence)
	}
	if count == 0 {
		return Section{
			Title:   "Evidence",
			Content: "Stored findings carry no attached evidence items yet (evidence attach lands with findings storage in v0.2).",
		}
	}
	return Section{
		Title: "Evidence",
		Content: fmt.Sprintf("%d evidence item(s) are attached across %d stored finding(s). Each finding references its evidence by content-addressed ID; evidence carries per-source provenance per §44 (organization/document/url/accessed). Full evidence is retrievable via the canonical JSON export (see 'riskx export jsonl').",
			count, len(findings)),
	}
}

func remediationSection(crit, high []models.Finding) Section {
	var remed []string
	for _, f := range append(crit, high...) {
		if f.Remediation == nil {
			continue
		}
		remed = append(remed, fmt.Sprintf("- %s (%s): %s — fix: %s",
			f.ID, f.Severity, f.Remediation.Problem, f.Remediation.Fix))
	}
	if len(remed) == 0 {
		return Section{
			Title:   "Remediation guidance",
			Content: "No open high or critical findings with remediation guidance in this report.",
		}
	}
	return Section{Title: "Remediation guidance", Content: strings.Join(remed, "\n")}
}

func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }

// ExportJSONL writes the full evidence (findings, scores, assets) as a JSONL
// stream with a provenance header line.
func ExportJSONL(in SummaryInput, w io.Writer) error {
	jw := NewJSONLWriter(w)
	return jw.Write(JSONLOptions{Findings: in.Findings, Scores: in.Scores, Assets: in.Assets})
}

// ExportCSV writes findings and scores as CSV. Each section is its own RFC
// 4180 record shape: callers wanting both should write to separate streams
// (one writer, one shape — documented limitation).
func ExportCSV(in SummaryInput, w io.Writer) error {
	cw := NewCSVWriter(w)
	if err := cw.Findings(in.Findings, time.Now().UTC()); err != nil {
		return fmt.Errorf("csv findings: %w", err)
	}
	if err := cw.Scores(in.Scores); err != nil {
		return fmt.Errorf("csv scores: %w", err)
	}
	return nil
}

// ExportSARIF writes findings as a SARIF 2.1.0 log (OASIS Standard + Errata 01).
func ExportSARIF(in SummaryInput, w io.Writer) error {
	sw := NewSARIFWriter(w)
	return sw.Write(in.Findings)
}

// HumanReport renders the JSON summary as plain-text sections with attribution.
func HumanReport(sum JSONSummary) string {
	var b strings.Builder
	b.WriteString("=== RISKX executive risk summary ===\n")
	b.WriteString(fmt.Sprintf("Model version: %s | Generated: %s\n\n", sum.Model, sum.GeneratedAt.Format(time.RFC3339)))
	for _, s := range sum.Sections {
		b.WriteString(fmt.Sprintf("--- %s ---\n%s\n\n", s.Title, s.Content))
	}
	if len(sum.Counts.FutureSections) > 0 {
		b.WriteString("--- future sections (deferred) ---\n")
		b.WriteString("The following sections are not yet implemented and are tracked as future phases; they are not fabricated:\n")
		for _, name := range sum.Counts.FutureSections {
			b.WriteString("- " + name + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(output.NVDAttribution)
	return b.String()
}

// MarshalJSONCanonical produces the canonical JSON bytes for the summary.
func MarshalJSONCanonical(sum JSONSummary) ([]byte, error) {
	return json.MarshalIndent(sum, "", "  ")
}
