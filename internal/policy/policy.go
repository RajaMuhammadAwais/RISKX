// Package policy implements the configurable policy engine (spec §33, §34).
//
// Policy is YAML-defined and evaluated over findings and risk scores. Detectors
// never hardcode policy (spec §34). Exit-code semantics (spec §33):
//  0 = no policy violation
//  1 = policy violation found (evaluation completed; findings exist that fail policy)
//  2 = execution error (policy file unreadable, malformed, etc.)
// The engine never returns 2 for "violations found": that is a clean policy
// outcome reported as exit code 1.
package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Policy is the top-level policy document.
type Policy struct {
	Rules []Rule `yaml:"rules"`
	// Defaults apply when no rule matches a finding.
	Defaults DefaultActions `yaml:"defaults,omitempty"`
}

// Rule is one named policy rule with a condition and action.
type Rule struct {
	Name   string       `yaml:"name"`
	When   Condition    `yaml:"when"`
	Action string       `yaml:"action"` // "fail" | "warn" | "none"
}

// Condition selects findings/risk scores the rule applies to.
type Condition struct {
	Severity      []string `yaml:"severity,omitempty"`      // any of
	MinScore      float64  `yaml:"min_score,omitempty"`
	InKEV         *bool    `yaml:"in_kev,omitempty"`
	InternetExposed *bool  `yaml:"internet_exposed,omitempty"`
	AdminExposed  *bool    `yaml:"internet_exposed_admin,omitempty"`
	CVE           []string `yaml:"cve,omitempty"`
}

// DefaultActions describes unmatched-finding behavior.
type DefaultActions struct {
	Action string `yaml:"action,omitempty"` // warn|none
}

// Outcome is the structured result of evaluating policy over a finding set.
type Outcome struct {
	Rule        string   `json:"rule" yaml:"rule"`
	FindingIDs  []string `json:"finding_ids" yaml:"finding_ids"`
	Action      string   `json:"action" yaml:"action"`
	Reason      string   `json:"reason" yaml:"reason"`
}

// Evaluation is the full policy evaluation result.
type Evaluation struct {
	PolicyFile string    `json:"policy_file" yaml:"policy_file"`
	Outcomes   []Outcome `json:"outcomes" yaml:"outcomes"`
	Violated   bool      `json:"violated" yaml:"violated"`
	Note       string    `json:"note,omitempty" yaml:"note,omitempty"`
}

// ExitCode maps an evaluation to the CLI exit code (spec §33).
func (e *Evaluation) ExitCode() int {
	if e.Violated {
		return 1
	}
	return 0
}

// DefaultPolicy returns the built-in policy baseline.
func DefaultPolicy() *Policy {
	fail := "fail"
	return &Policy{
		Rules: []Rule{
			{Name: "critical_risk", When: Condition{MinScore: 90}, Action: fail},
			{Name: "kev", When: Condition{InKEV: boolPtr(true)}, Action: fail},
			{Name: "internet_exposed_admin", When: Condition{AdminExposed: boolPtr(true)}, Action: fail},
		},
		Defaults: DefaultActions{Action: "warn"},
	}
}

func boolPtr(b bool) *bool { return &b }

// Load reads a policy file; a missing file falls back to the built-in policy.
func Load(path string) (*Policy, error) {
	if path == "" {
		return DefaultPolicy(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, errs.Wrap(errs.CodeConfigError, "policy.load", "cannot read policy file", err)
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, errs.Wrap(errs.CodeConfigError, "policy.load", "malformed policy file", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	for _, r := range p.Rules {
		if r.Name == "" {
			return errs.Input("policy.validate", "rule missing name", "add a name to each rule")
		}
		switch r.Action {
		case "fail", "warn", "none":
		default:
			return errs.Input("policy.validate",
				fmt.Sprintf("rule %q has unsupported action %q", r.Name, r.Action),
				"actions must be 'fail', 'warn', or 'none'")
		}
	}
	return nil
}

// Evaluate applies the policy to findings with their risk scores. Active,
// non-expired suppressions exclude findings from evaluation (spec §30).
func Evaluate(p *Policy, findings []models.Finding, scores []models.RiskScore, now time.Time) *Evaluation {
	scoreOf := make(map[string]models.RiskScore, len(scores))
	for _, s := range scores {
		scoreOf[s.AssetID] = s
	}
	eval := &Evaluation{Outcomes: []Outcome{}}
	for _, rule := range p.Rules {
		var hits []string
		for _, f := range findings {
			if f.Suppression != nil && f.Suppression.IsActive(now) {
				continue // explicit, time-boxed exception (spec §30)
			}
			if !rule.When.matches(f, scoreOf[f.AssetID]) {
				continue
			}
			hits = append(hits, f.ID)
		}
		if len(hits) == 0 {
			continue
		}
		violated := rule.Action == "fail"
		if violated {
			eval.Violated = true
		}
		eval.Outcomes = append(eval.Outcomes, Outcome{
			Rule:       rule.Name,
			FindingIDs: hits,
			Action:     rule.Action,
			Reason:     rule.Name + " condition matched",
		})
	}
	return eval
}

// matches reports whether the condition selects the finding.
func (c Condition) matches(f models.Finding, s models.RiskScore) bool {
	if len(c.Severity) > 0 {
		hit := false
		for _, sev := range c.Severity {
			if string(f.Severity) == sev {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if c.MinScore > 0 && s.Score < c.MinScore {
		return false
	}
	if c.InKEV != nil {
		if *c.InKEV && !f.InKEV() {
			return false
		}
	}
	if c.InternetExposed != nil && *c.InternetExposed {
		if f.ExposureLevel() != models.ExposureInternet {
			return false
		}
	}
	if c.AdminExposed != nil && *c.AdminExposed {
		if f.ExposureLevel() != models.ExposureInternet || !f.IsAdmin() {
			return false
		}
	}
	if len(c.CVE) > 0 {
		hit := false
		for _, id := range c.CVE {
			if f.ReferencesCVE(id) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}


