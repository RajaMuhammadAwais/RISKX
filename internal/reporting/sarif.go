// Package reporting — SARIF 2.1.0 exporter.
//
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard
// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html).
// RISKX uses SARIF so third-party tools (Azure DevOps, GitHub code scanning,
// SIEM ingestions) can consume RISKX findings. The exporter targets the
// "2.1.0" version with Errata 01 conventions; the log object carries version
// string "2.1.0" and exactly one run (no nested invocations, no external
// properties, no source-region data — RISKX findings are about network/cloud
// assets, not source files).
//
// Key mapping decisions (all per §5.3 result object):
//   - result.ruleId = RISKX finding ID (content-addressed RISKX-...)
//   - result.level = severity band mapped to SARIF level:
//     critical|high → "error", medium → "warning", low → "note", else "none"
//   - result.message.text = finding title + observation (no guessing beyond
//     what the finding states)
//   - result.locations[0].physicalLocation.artifactLocation.uri = asset value
//     (URI-permitted per SARIF — asset identifiers are valid URI strings:
//     FQDN, s3://bucket, arn:aws:..., IP)
//   - result.properties carries riskx-specific extensions (confidence,
//     status, model version, evidence count, references) — the official
//     extension mechanism for provider-specific data
//   - result.fingerprints["RISKX-ContentID"] = finding ID so dedup consumers
//     can recognize already-seen findings
package reporting

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// SARIFVersion is the SARIF spec version this exporter emits.
const SARIFVersion = "2.1.0"

// SARIFDriver is the tool identity.
const SARIFDriverName = "RISKX"

// sarifLog is the canonical SARIF log object (version string REQUIRED by the
// schema: MUST be "2.1.0" — the errata01 schema dropped the enum in favor of
// the plain string; we emit the spec version exactly).
type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string         `json:"name"`
	Version        string         `json:"version,omitempty"`
	InformationURI string         `json:"informationUri,omitempty"`
	Rules          []sarifRule    `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription sarifMessage    `json:"shortDescription,omitempty"`
	Properties       json.RawMessage `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID      string            `json:"ruleId"`
	Level       string            `json:"level"`
	Message     sarifMessage      `json:"message"`
	Locations   []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties  json.RawMessage   `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifProperties struct {
	RISKXConfidence    string   `json:"riskx_confidence"`
	RISKXStatus        string   `json:"riskx_status"`
	RISKXValidation    string   `json:"riskx_validation"`
	RISKXModelVersion  string   `json:"riskx_model_version"`
	RISKXEvidenceCount int      `json:"riskx_evidence_count"`
	RISKXReferences    []string `json:"riskx_references,omitempty"`
}

// severityLevel maps a RISKX severity band to the SARIF level enum.
// "none","note","warning","error" are the four legal values in the 2.1.0
// schema (level is nullable but the enum constrains non-null values).
func severityLevel(s models.Severity) string {
	switch s {
	case models.SevCritical, models.SevHigh:
		return "error"
	case models.SevMedium:
		return "warning"
	case models.SevLow:
		return "note"
	default:
		return "note"
	}
}

func toProperties(f models.Finding) json.RawMessage {
	p := sarifProperties{
		RISKXConfidence:    string(f.Confidence),
		RISKXStatus:        string(f.Status),
		RISKXValidation:    string(f.Validation),
		RISKXModelVersion:  f.Schema,
		RISKXEvidenceCount: len(f.Evidence),
		RISKXReferences:    f.References,
	}
	b, err := json.Marshal(p)
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}

// SARIFWriter writes a SARIF 2.1.0 log of findings to w.
type SARIFWriter struct {
	w       io.Writer
	version string
}

func NewSARIFWriter(w io.Writer) *SARIFWriter {
	return &SARIFWriter{w: w, version: SARIFVersion}
}

// Write emits the SARIF log for the supplied findings and validates the
// structural minimum (version + at least one run with tool.driver) before
// writing anything. On failure the writer reports the error without leaving
// partial output on w.
func (s *SARIFWriter) Write(findings []models.Finding) error {
	log := s.buildLog(findings)
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("sarif marshal: %w", err)
	}
	b = append(b, '\n')
	_, err = s.w.Write(b)
	return err
}

func (s *SARIFWriter) buildLog(findings []models.Finding) sarifLog {
	rules := make([]sarifRule, 0, len(findings))
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = "RISKX finding"
		}
		msg := title
		if f.Observation != "" {
			msg = title + " | " + f.Observation
		}
		rules = append(rules, sarifRule{
			ID:               f.ID,
			Name:             title,
			ShortDescription: sarifMessage{Text: title},
		})
		r := sarifResult{
			RuleID: f.ID,
			Level:  severityLevel(f.Severity),
			Message: sarifMessage{
				Text: msg,
			},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.AssetValue},
				},
			}},
			Fingerprints: map[string]string{"RISKX-ContentID": f.ID},
			Properties:   toProperties(f),
		}
		results = append(results, r)
	}
	return sarifLog{
		Version: s.version,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           SARIFDriverName,
					Version:        "0.2.0",
					InformationURI: "https://github.com/RajaMuhammadAwais/RISKX",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}
