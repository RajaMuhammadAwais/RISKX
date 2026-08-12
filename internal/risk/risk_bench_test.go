package risk

import (
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// BenchmarkRiskScore measures deterministic scoring of a fully-evidenced
// enterprise asset: internet exposure, KEV-linked vulnerability, criticality.
func BenchmarkRiskScore(b *testing.B) {
	engine, err := NewEngine(nil)
	if err != nil {
		b.Fatalf("engine creation failed: %v", err)
	}
	in := InputBundle{
		AssetID:        "asset-web-01",
		Exposure:       models.ExposureInternet,
		Criticality:    0.9,
		KEV:            true,
		ScoreAvailable: true,
		MaxCVSS:        9.8,
		Centrality:     0.75,
		Evidence: []models.Evidence{
			{Type: "internet", Timestamp: time.Now().UTC()},
			{Type: "kev", Timestamp: time.Now().UTC()},
			{Type: "feed", Timestamp: time.Now().UTC()},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Score(in)
	}
}
