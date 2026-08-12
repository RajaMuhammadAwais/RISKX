package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func TestJSONOutputIsCanonical(t *testing.T) {
	meta := NewMeta("passive")
	r := Result{Meta: meta, Payload: map[string]any{"x": 1}}
	var buf bytes.Buffer
	p := NewPrinter(&buf)
	if err := p.EmitJSON(r); err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output must be valid canonical JSON: %v", err)
	}
	if decoded.Meta.Tool != "riskx" || decoded.Meta.ToolVersion == "" {
		t.Fatal("metadata identity missing from output")
	}
}

func TestNVDAttributionInjected(t *testing.T) {
	meta := NewMeta("passive")
	meta.Feeds = []models.FeedStatus{{Feed: "nvd"}}
	var buf bytes.Buffer
	p := NewPrinter(&buf)
	r := Result{Meta: meta, Payload: nil}
	AddNVDAttribution(&r.Meta)
	if err := p.HumanSummary(r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), NVDAttribution) {
		t.Fatalf("NVD-sourced output must carry attribution; got:\n%s", buf.String())
	}
}

func TestNVDAttributionNeverDuplicated(t *testing.T) {
	meta := NewMeta("passive")
	meta.Feeds = []models.FeedStatus{{Feed: "nvd"}}
	AddNVDAttribution(&meta)
	AddNVDAttribution(&meta)
	n := 0
	for _, a := range meta.Attribution {
		if a == NVDAttribution {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("attribution must appear exactly once, got %d", n)
	}
}

func TestNoNVDDataNoAttribution(t *testing.T) {
	meta := NewMeta("passive")
	meta.Feeds = []models.FeedStatus{{Feed: "kev"}}
	AddNVDAttribution(&meta)
	if len(meta.Attribution) != 0 {
		t.Fatal("non-NVD output must not carry NVD attribution")
	}
}

func TestStaleFeedRendered(t *testing.T) {
	meta := NewMeta("passive")
	meta.Feeds = []models.FeedStatus{{Feed: "kev", Stale: true}}
	var buf bytes.Buffer
	p := NewPrinter(&buf)
	if err := p.HumanSummary(Result{Meta: meta}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "STALE") {
		t.Fatal("stale feed must be visibly marked STALE in human output")
	}
}
