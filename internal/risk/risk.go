// Package risk implements the risk-v1 deterministic scoring model
// (docs/architecture/architecture-v1.md §4).
//
// Design constraints (spec §12, §20, §48):
//   - The score is a weighted sum of seven named, evidence-backed factors.
//   - Every factor reports its evidence and citation; the model version and
//     weights are emitted with every score.
//   - Factors are never guessed: missing evidence caps the factor at 0 with
//     the input recorded in incomplete_inputs, never silently assumed safe.
//   - Stale inputs are recorded in stale_inputs; the score never pretends
//     stale data is current.
//   - AI never produces or adjusts the score; it may only assist explanation
//     downstream (Phase 10).
package risk

import (
	"fmt"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/evidence"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// ModelVersion is the current risk model identifier (spec §45).
const ModelVersion = "risk-v1"

// Factor names, in canonical order.
const (
	FactorExposure       = "exposure"
	FactorKnownExploit   = "known_exploitation"
	FactorPredExploit    = "predicted_exploitation"
	FactorCriticality    = "criticality"
	FactorAttackPath     = "attack_path_position"
	FactorIdentity       = "identity_privilege"
	FactorStandardsGap   = "standards_gap"
)

// DefaultWeights sum to 1.0. Overridable per config (ADR-0003 note on
// risk-v1 configuration).
var DefaultWeights = map[string]float64{
	FactorExposure:     0.20,
	FactorKnownExploit: 0.20,
	FactorPredExploit:  0.15,
	FactorCriticality:  0.15,
	FactorAttackPath:   0.10,
	FactorIdentity:     0.10,
	FactorStandardsGap: 0.10,
}

// EPSSStaleDays is the default EPSS freshness bound (per docs/research/
// vulnerability-intelligence.md).
const EPSSStaleDays = 7

// InputBundle is the evidence-tagged input per asset for one scoring run.
type InputBundle struct {
	AssetID   string
	Exposure  models.ExposureLevel
	Criticality float64 // 0..1, from classification or policy default
	KEV       bool      // CISA KEV membership evidence
	EPSS      *models.EPSSReading
	ScoreAvailable bool // a CVSS score was imported for the relevant vulns
	MaxCVSS        float64
	Centrality     float64 // 0..1 normalized centrality (Phase 5)
	HighPrivilege  bool    // identity-privilege evidence (Phase 6)
	StandardsGap   float64 // 0..1 CIS IG1/CPG gap evidence
	Evidence       []models.Evidence
	StaleInputs    []string
}

// Engine scores assets deterministically.
type Engine struct {
	weights map[string]float64
	now     time.Time
}

// NewEngine builds an engine with the given weight overrides (may be nil).
func NewEngine(overrides map[string]float64) (*Engine, error) {
	w := make(map[string]float64, len(DefaultWeights))
	for k, v := range DefaultWeights {
		w[k] = v
	}
	for k, v := range overrides {
		if _, ok := DefaultWeights[k]; !ok {
			return nil, errs.Input("risk.new",
				fmt.Sprintf("unknown risk factor %q", k),
				fmt.Sprintf("factors: %v", factorList()))
		}
		if v < 0 || v > 1 {
			return nil, errs.Input("risk.new",
				fmt.Sprintf("weight for %q out of range [0,1]", k),
				"weights must be between 0 and 1")
		}
		w[k] += v // overrides add to the defaults, preserving coverage
	}
	var sum float64
	for _, v := range w {
		sum += v
	}
	if sum <= 0 {
		return nil, errs.Input("risk.new", "effective weight sum is zero",
			"at least one factor weight must be positive")
	}
	// Normalize so weights always sum to 1 regardless of overrides.
	for k := range w {
		w[k] /= sum
	}
	return &Engine{weights: w, now: time.Now().UTC()}, nil
}

func factorList() []string {
	out := make([]string, 0, len(DefaultWeights))
	for k := range DefaultWeights {
		out = append(out, k)
	}
	return out
}

// Score computes risk-v1 for one asset. Missing evidence caps factors at 0
// and is recorded in incomplete_inputs (spec §48); stale inputs are recorded.
func (e *Engine) Score(in InputBundle) models.RiskScore {
	var (
		factors    []models.RiskFactor
		incomplete []string
		stale      []string
		total      float64
	)

	// Exposure (E): internet=1.0, internal=0.5, unknown=0 (recorded incomplete).
	expVal := 0.0
	switch in.Exposure {
	case models.ExposureInternet:
		expVal = 1.0
	case models.ExposureInternal:
		expVal = 0.5
	default:
		incomplete = append(incomplete, "no exposure evidence")
	}
	total += e.addFactor(&factors, FactorExposure, expVal, in.Evidence)

	// Known exploitation (K): KEV membership.
	kevVal := 0.0
	if in.KEV {
		kevVal = 1.0
	}
	total += e.addFactor(&factors, FactorKnownExploit, kevVal, in.Evidence)

	// Predicted exploitation (P): EPSS, capped at stale (recorded stale).
	epssVal := 0.0
	if in.EPSS != nil {
		epssVal = in.EPSS.Score
		if epssStale(e.now, in.EPSS.Date) || in.EPSS.Stale {
			stale = append(stale, "epss")
		}
	} else {
		incomplete = append(incomplete, "no EPSS data")
	}
	total += e.addFactor(&factors, FactorPredExploit, epssVal, in.Evidence)

	// Criticality (C): explicit value or incomplete.
	critVal := 0.0
	if in.Criticality > 0 {
		critVal = clamp(in.Criticality)
	} else {
		incomplete = append(incomplete, "no criticality classification")
	}
	total += e.addFactor(&factors, FactorCriticality, critVal, in.Evidence)

	// Attack-path position (A): centrality; 0 when graph data absent.
	if in.Centrality > 0 {
		total += e.addFactor(&factors, FactorAttackPath, clamp(in.Centrality), in.Evidence)
	} else {
		incomplete = append(incomplete, "no attack-graph data")
		total += e.addFactor(&factors, FactorAttackPath, 0, in.Evidence)
	}

	// Identity privilege (I): high-privilege evidence.
	idVal := 0.0
	if in.HighPrivilege {
		idVal = 1.0
	} else {
		incomplete = append(incomplete, "no identity-privilege evidence")
	}
	total += e.addFactor(&factors, FactorIdentity, idVal, in.Evidence)

	// Standards gap (S): CIS IG1 / CPG gap evidence.
	gapVal := 0.0
	if in.StandardsGap > 0 {
		gapVal = clamp(in.StandardsGap)
	} else {
		incomplete = append(incomplete, "no standards-gap evidence")
	}
	total += e.addFactor(&factors, FactorStandardsGap, gapVal, in.Evidence)

	return models.RiskScore{
		AssetID:      in.AssetID,
		Score:        clamp(total) * 100,
		Severity:     band(clamp(total)*100),
		Factors:      factors,
		Weights:      e.weights,
		Evidence:     in.Evidence,
		ModelVersion: ModelVersion,
		Stale:        stale,
		Incomplete:   incomplete,
	}
}

func (e *Engine) addFactor(fs *[]models.RiskFactor, name string, value float64, ev []models.Evidence) float64 {
	w := e.weights[name]
	*fs = append(*fs, models.RiskFactor{
		Name:     name,
		Weight:   w,
		Value:    clamp(value),
		Evidence: ev,
		Citation: fmt.Sprintf("risk model %s, weight %.2f", ModelVersion, w),
	})
	return w * clamp(value)
}

// epssStale reports whether an EPSS reading is older than the freshness bound.
func epssStale(now time.Time, dateStr string) bool {
	if dateStr == "" {
		return true
	}
	d, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return true
	}
	return now.Sub(d).Hours() > float64(EPSSStaleDays*24)
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// band maps a 0..100 score to a reporting severity band.
func band(score float64) models.Severity {
	switch {
	case score >= 90:
		return models.SevCritical
	case score >= 70:
		return models.SevHigh
	case score >= 40:
		return models.SevMedium
	case score >= 1:
		return models.SevLow
	default:
		return models.SevInfo
	}
}

// CitedSources returns the research sources the model's factors reference.
func CitedSources() []evidence.Source {
	return []evidence.Source{
		evidence.CISAKEV, evidence.FIRSTEPSS, evidence.CISControls,
	}
}
