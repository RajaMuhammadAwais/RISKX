package risk

import (
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestScoreRange(t *testing.T) {
	e := newTestEngine(t)
	in := InputBundle{
		AssetID: "a1", Exposure: models.ExposureInternet, Criticality: 1.0,
		KEV: true, EPSS: &models.EPSSReading{Score: 0.9, Date: time.Now().UTC().Format("2006-01-02")},
		ScoreAvailable: true, MaxCVSS: 10, Centrality: 0.8, HighPrivilege: true,
		StandardsGap: 0.9,
	}
	s := e.Score(in)
	if s.Score < 0 || s.Score > 100 {
		t.Fatalf("score out of range: %f", s.Score)
	}
	if s.Severity != models.SevCritical {
		t.Fatalf("max-input asset must be critical, got %s (score %.1f)", s.Severity, s.Score)
	}
	if s.ModelVersion != ModelVersion {
		t.Fatal("model version must be risk-v1")
	}
	if len(s.Stale) != 0 {
		t.Fatal("fresh inputs must not produce stale markers")
	}
}

func TestScoreNoEvidenceNoGuess(t *testing.T) {
	e := newTestEngine(t)
	s := e.Score(InputBundle{AssetID: "a1", Exposure: models.ExposureUnknown})
	if s.Score != 0 {
		t.Fatalf("asset with no evidence must score 0, got %.1f", s.Score)
	}
	if len(s.Incomplete) == 0 {
		t.Fatal("missing evidence must be listed in incomplete_inputs, not silently assumed safe")
	}
}

func TestEPSSStaleMarked(t *testing.T) {
	e := newTestEngine(t)
	in := InputBundle{
		AssetID: "a1", Exposure: models.ExposureInternet,
		EPSS: &models.EPSSReading{Score: 0.9, Date: "2000-01-01"},
	}
	s := e.Score(in)
	if len(s.Stale) == 0 {
		t.Fatal("stale EPSS must be recorded in stale_inputs")
	}
}

func TestEPSSMissingMarkedIncomplete(t *testing.T) {
	e := newTestEngine(t)
	s := e.Score(InputBundle{AssetID: "a1", Exposure: models.ExposureInternet})
	if len(s.Incomplete) == 0 {
		t.Fatal("missing EPSS must appear in incomplete_inputs")
	}
}

func TestWeightNormalization(t *testing.T) {
	// Overrides ADD to defaults; the returned weights are always normalized to 1.
	e, err := NewEngine(map[string]float64{FactorExposure: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, v := range e.weights {
		sum += v
	}
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("weights must normalize to 1, got %.4f", sum)
	}
	// The boosted factor must outweigh its default share.
	if e.weights[FactorExposure] <= DefaultWeights[FactorExposure] {
		t.Fatal("override must increase the factor's normalized weight")
	}
}

func TestUnknownFactorRejected(t *testing.T) {
	_, err := NewEngine(map[string]float64{"bogus": 0.5})
	if err == nil {
		t.Fatal("unknown risk factor must be rejected")
	}
}

func TestBandMapping(t *testing.T) {
	cases := []struct {
		score float64
		want  models.Severity
	}{
		{95, models.SevCritical}, {80, models.SevHigh}, {50, models.SevMedium},
		{20, models.SevLow}, {0, models.SevInfo},
	}
	for _, c := range cases {
		if got := band(c.score); got != c.want {
			t.Errorf("band(%.0f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestInternalExposureScoresHalfExposureWeight(t *testing.T) {
	e := newTestEngine(t)
	external := e.Score(InputBundle{AssetID: "a1", Exposure: models.ExposureInternet})
	internal := e.Score(InputBundle{AssetID: "a1", Exposure: models.ExposureInternal})
	if internal.Score >= external.Score {
		t.Fatalf("internal exposure must score lower than internet: %.1f >= %.1f", internal.Score, external.Score)
	}
}
