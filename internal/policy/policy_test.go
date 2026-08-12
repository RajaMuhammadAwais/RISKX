package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

func TestDefaultPolicyRejectsKEVAndCritical(t *testing.T) {
	p := DefaultPolicy()
	now := time.Now()
	findings := []models.Finding{
		{ID: "f1", AssetID: "a1", Severity: models.SevLow,
			Evidence: []models.Evidence{{Type: "kev"}},
			References: []string{"CVE-2021-44228"}},
		{ID: "f2", AssetID: "a2", Severity: models.SevLow,
			Evidence: []models.Evidence{{Type: "admin_panel_exposed"}, {Type: "internet"}}},
	}
	scores := []models.RiskScore{
		{AssetID: "a1", Score: 50},
		{AssetID: "a2", Score: 40},
	}
	eval := Evaluate(p, findings, scores, now)
	if !eval.Violated {
		t.Fatal("default policy must flag KEV and admin-exposed findings")
	}
	if eval.ExitCode() != 1 {
		t.Fatalf("violated policy must exit 1, got %d", eval.ExitCode())
	}
	if len(eval.Outcomes) < 2 {
		t.Fatalf("expected >=2 outcomes, got %d", len(eval.Outcomes))
	}
}

func TestSuppressedFindingExcludedFromEvaluation(t *testing.T) {
	p := DefaultPolicy()
	now := time.Now()
	f := models.Finding{
		ID: "f1", AssetID: "a1", Severity: models.SevLow,
		Evidence: []models.Evidence{{Type: "kev"}},
		Suppression: &models.Suppression{
			Reason: "patching in progress", Owner: "ops@example.com",
			CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		},
	}
	eval := Evaluate(p, []models.Finding{f}, nil, now)
	if eval.Violated {
		t.Fatal("active suppression must exclude the finding from KEV rule")
	}
}

func TestExpiredSuppressionDoesNotExclude(t *testing.T) {
	p := DefaultPolicy()
	now := time.Now()
	f := models.Finding{
		ID: "f1", AssetID: "a1", Severity: models.SevLow,
		Evidence: []models.Evidence{{Type: "kev"}},
		Suppression: &models.Suppression{
			Reason: "expired", Owner: "ops@example.com",
			CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour),
		},
	}
	eval := Evaluate(p, []models.Finding{f}, nil, now)
	if !eval.Violated {
		t.Fatal("expired suppression must not exclude the finding")
	}
}

func TestCleanRunExitsZero(t *testing.T) {
	p := DefaultPolicy()
	findings := []models.Finding{
		{ID: "f1", AssetID: "a1", Severity: models.SevInfo,
			Evidence: []models.Evidence{{Type: "informational"}}},
	}
	eval := Evaluate(p, findings, []models.RiskScore{{AssetID: "a1", Score: 5}}, time.Now())
	if eval.Violated || eval.ExitCode() != 0 {
		t.Fatal("low-score non-KEV finding must not violate default policy")
	}
}

func TestLoadMalformedPolicyFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("rules:\n  - name: x\n    when: {min_score: abc}\n"), 0600)
	_, err := Load(p)
	if err == nil {
		t.Fatal("malformed policy must fail to load")
	}
}

func TestPolicyUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	os.WriteFile(p, []byte("unknown_key: 1\n"), 0600)
	_, err := Load(p)
	if err == nil {
		t.Fatal("unknown policy fields must be rejected")
	}
}

func TestConditionMinScore(t *testing.T) {
	c := Condition{MinScore: 90}
	if c.matches(models.Finding{}, models.RiskScore{Score: 89}) {
		t.Fatal("89 must not match min_score 90")
	}
	if !c.matches(models.Finding{}, models.RiskScore{Score: 90}) {
		t.Fatal("90 must match min_score 90")
	}
}
