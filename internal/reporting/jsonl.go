package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// jsonlHeaderLine is the first line of a RISKX JSONL stream. It is a JSON
// object so consumers can parse every line with the same decoder; the first
// line carries metadata and every subsequent line carries exactly one record.
// This follows the JSONL convention: one JSON value per line, no trailing
// commas, no outer array (spec §38: JSON is the canonical machine format).
type jsonlHeaderLine struct {
	Schema      string    `json:"schema"`
	Model       string    `json:"model_version"`
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`
	RecordCount int       `json:"record_count"`
	Attribution []string  `json:"attribution,omitempty"`
}

// JSONLOptions controls what a JSONLWriter serializes.
type JSONLOptions struct {
	Findings []models.Finding `json:"findings,omitempty"`
	Scores   []models.RiskScore `json:"scores,omitempty"`
	Assets   []models.Asset   `json:"assets,omitempty"`
}

// JSONLWriter writes a JSONL stream: one metadata header line followed by
// exactly one canonical JSON object per line, in the order findings, scores,
// assets. Every line is independently valid JSON so the stream is resumable
// and grep/awk-friendly; the header line carries model versions and NVD
// attribution so provenance travels with the data.
type JSONLWriter struct {
	w io.Writer
}

func NewJSONLWriter(w io.Writer) *JSONLWriter {
	return &JSONLWriter{w: w}
}

// Write emits the header plus all records and flushes.
func (j *JSONLWriter) Write(opts JSONLOptions) error {
	header := jsonlHeaderLine{
		Schema:      "report-v1",
		Model:       ModelVersion,
		Format:      "jsonl",
		GeneratedAt: time.Now().UTC(),
		RecordCount: len(opts.Findings) + len(opts.Scores) + len(opts.Assets),
		Attribution: []string{output.NVDAttribution},
	}
	if err := j.writeLine(header); err != nil {
		return fmt.Errorf("jsonl header: %w", err)
	}
	for i := range opts.Findings {
		if err := j.writeLine(opts.Findings[i]); err != nil {
			return fmt.Errorf("jsonl finding %d: %w", i, err)
		}
	}
	for i := range opts.Scores {
		if err := j.writeLine(opts.Scores[i]); err != nil {
			return fmt.Errorf("jsonl score %d: %w", i, err)
		}
	}
	for i := range opts.Assets {
		if err := j.writeLine(opts.Assets[i]); err != nil {
			return fmt.Errorf("jsonl asset %d: %w", i, err)
		}
	}
	if f, ok := j.w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	return nil
}

func (j *JSONLWriter) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(j.w, "%s\n", b)
	return err
}

// ParseJSONL parses a RISKX JSONL stream back into its header and records.
// Provided for roundtrip tests and consumer tooling; production consumers may
// parse line-by-line instead of buffering the whole stream.
func ParseJSONL(data []byte) (*jsonlHeaderLine, []json.RawMessage, error) {
	var lines []json.RawMessage
	for len(data) > 0 {
		var line json.RawMessage
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&line); err != nil {
			return nil, nil, fmt.Errorf("jsonl parse: %w", err)
		}
		lines = append(lines, line)
		data = data[dec.InputOffset():]
		for len(data) > 0 && data[0] == '\n' {
			data = data[1:]
		}
	}
	if len(lines) == 0 {
		return nil, nil, fmt.Errorf("jsonl: empty stream")
	}
	var hdr jsonlHeaderLine
	if err := json.Unmarshal(lines[0], &hdr); err != nil {
		return nil, nil, fmt.Errorf("jsonl header: %w", err)
	}
	if hdr.Format != "jsonl" {
		return nil, nil, fmt.Errorf("jsonl header: unsupported format %q", hdr.Format)
	}
	return &hdr, lines[1:], nil
}
