package reporting

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// jsonschema/v5 is used deliberately: v6 introduced metaschema revalidation
// of the schema document itself, which rejects the official OASIS draft-04
// artifact even when $schema is injected; v5 compiles the artifact as
// published without that constraint.

// schemaID is the authoritative identifier of the official OASIS SARIF 2.1.0
// Errata 01 schema. The document itself was published against JSON Schema
// draft-04 (it predates $schema).
const schemaID = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// loadSARIFSchema compiles the official schema bundled at
// docs/research/schemas/sarif-schema-2.1.0.json. The bundled file is the
// canonical spec artifact (never a third-party copy); we register it under
// its own published id so internal $ref chains resolve deterministically,
// and inject $schema:draft-04 because the OASIS document predates that
// convention — documented decision, not a guess.
func loadSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	p := schemaPath()
	if p == "" {
		t.Skip("official SARIF schema not found; download it per research doc")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if !bytes.Contains(b, []byte(`"$schema"`)) {
		b = injectDraft04(b)
		// Rewrite so the compiled copy and the on-disk copy agree.
		if err := os.WriteFile(p, b, 0644); err != nil {
			t.Fatalf("write schema: %v", err)
		}
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft4 // the errata01 document is a draft-04 schema
	if err := compiler.AddResource(schemaID, bytes.NewReader(b)); err != nil {
		t.Fatalf("load schema: %v", err)
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// injectDraft04 prepends a $schema declaration to raw schema bytes.
func injectDraft04(b []byte) []byte {
	first := bytes.IndexByte(b, '{')
	if first < 0 {
		return b
	}
	decl := []byte(`{"$schema": "http://json-schema.org/draft-04/schema#",`)
	out := make([]byte, 0, len(decl)+len(b))
	out = append(out, decl...)
	out = append(out, b[first+1:]...)
	return out
}

// schemaPath locates the official SARIF schema bundled in the repo.
func schemaPath() string {
	candidates := []string{
		filepath.Join("..", "..", "docs", "research", "schemas", "sarif-schema-2.1.0.json"),
		filepath.Join(".", "docs", "research", "schemas", "sarif-schema-2.1.0.json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func TestSARIFEmitsVersionTwoPointOneZero(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf)
	if err := w.Write(sampleFindings()); err != nil {
		t.Fatalf("write: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if raw["version"] != "2.1.0" {
		t.Errorf("version: got %v, want 2.1.0", raw["version"])
	}
	runs, ok := raw["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs: want exactly one run, got %v", raw["runs"])
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf)
	if err := w.Write(sampleFindings()); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	results := out["runs"].([]any)[0].(map[string]any)["results"].([]any)
	want := map[string]string{
		"RISKX-abc123": "error",   // critical → error
		"RISKX-def456": "warning", // medium → warning
		"RISKX-sup1":   "note",    // low → note
		"RISKX-exp1":   "error",   // high → error
	}
	for _, r := range results {
		res := r.(map[string]any)
		ruleID := res["ruleId"].(string)
		if wantL, ok := want[ruleID]; ok && res["level"] != wantL {
			t.Errorf("rule %s level: got %v, want %s", ruleID, res["level"], wantL)
		}
	}
}

func TestSARIFFingerprintsAndLocations(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf)
	if err := w.Write(sampleFindings()); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := map[string]any{}
	_ = json.Unmarshal(buf.Bytes(), &out)
	results := out["runs"].([]any)[0].(map[string]any)["results"].([]any)
	for _, r := range results {
		res := r.(map[string]any)
		fp := res["fingerprints"].(map[string]any)
		if fp["RISKX-ContentID"] != res["ruleId"] {
			t.Errorf("fingerprint mismatch for %v", res["ruleId"])
		}
		locs := res["locations"].([]any)
		if len(locs) != 1 {
			t.Errorf("want 1 location, got %d", len(locs))
			continue
		}
		uri := locs[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
		if uri == "" {
			t.Errorf("empty artifact URI for %v", res["ruleId"])
		}
	}
}

func TestSARIFValidatesAgainstOfficialSchema(t *testing.T) {
	schema := loadSARIFSchema(t)
	cases := []struct {
		name     string
		findings []models.Finding
	}{
		{"with findings", sampleFindings()},
		{"empty findings", nil},
		{"single critical", sampleFindings()[:1]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewSARIFWriter(&buf)
			if err := w.Write(c.findings); err != nil {
				t.Fatalf("write: %v", err)
			}
			var doc any
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("schema validation failed:\n%s\noutput was:\n%s", err, buf.String())
			}
		})
	}
}

func TestSARIFInvalidDocumentIsRejected(t *testing.T) {
	schema := loadSARIFSchema(t)
	doc := map[string]any{"version": "2.0.0", "runs": "not-an-array"}
	if err := schema.Validate(doc); err == nil {
		t.Error("expected schema rejection of malformed document, got none")
	} else if !strings.Contains(err.Error(), "version") {
		t.Logf("rejection error (expected): %v", err)
	}
}
