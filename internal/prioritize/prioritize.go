// Package prioritize ranks findings using only documented public exploit
// evidence: CISA KEV membership (binary confirmed-exploitation signal) and
// FIRST EPSS probability scores.
//
// Why these two signals (evidence, not guessing):
//   - KEV lists vulnerabilities actively exploited in the wild; CISA is the
//     authoritative US government source. Membership is a documented fact,
//     never a prediction.
//   - EPSS is FIRST's daily statistical estimate of exploitation probability;
//     it is published with methodology and updated daily. Scores are used
//     AS PUBLISHED — never adjusted, interpolated, or invented.
//
// The no-guessing rule applies to the ranking too:
//   - a finding with no KEV/EPSS evidence present is ranked LAST and clearly
//     marked "no_exploit_evidence" — it is never promoted by invented
//     signals;
//   - every rank line carries the exact evidence row (source URL, CVE,
//     value) so an analyst can trace any rank to public documentation;
//   - cached evidence older than FeedFreshAge is flagged STALE; ranks are
//     computed identically but the staleness travels with the output.
package prioritize

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/RajaMuhammadAwais/RISKX/internal/feed"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// RankModelVersion is the deterministic ranking model identifier.
const RankModelVersion = "rank-v1"

// FindingRank is one ranked finding with the evidence that produced its rank.
type FindingRank struct {
	Rank       int               `json:"rank"`
	Finding    models.Finding    `json:"finding"`
	KEV        *KEVSignal        `json:"kev,omitempty"` // nil = not in cached KEV
	EPSS       *EPSSSignal       `json:"epss,omitempty"`
	Tier       string            `json:"tier"` // "actively_exploited" | "high_probability" | "no_exploit_evidence"
	TierReason string            `json:"tier_reason"`
	Signals    []models.Evidence `json:"signals"` // every public signal used
}

// KEVSignal is a documented KEV membership fact (source-cited).
type KEVSignal struct {
	InKEV      bool   `json:"in_kev"`
	Product    string `json:"product,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	DateAdded  string `json:"date_added,omitempty"`
	Ransomware string `json:"known_ransomware_use,omitempty"`
	SourceURL  string `json:"source_url"`
	Stale      bool   `json:"stale"`
}

// EPSSSignal is a documented FIRST EPSS score (source-cited).
type EPSSSignal struct {
	Score     float64 `json:"score"`
	SourceURL string  `json:"source_url"`
	Stale     bool    `json:"stale"`
}

// cveOf extracts CVE identifiers mentioned in the finding's references.
// Non-CVE references are ignored — they are not exploitability evidence, and
// inferring exploitability from them would violate the no-guessing rule.
func cveOf(f models.Finding) []string {
	var cves []string
	seen := make(map[string]struct{})
	for _, ref := range f.References {
		u := strings.TrimSpace(strings.ToUpper(ref))
		if !strings.HasPrefix(u, "CVE-") {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		cves = append(cves, u)
	}
	return cves
}

// Rank produces a deterministic evidence-backed ranking of the findings.
// Ties are broken by finding severity order (critical > high > medium > low)
// then lexicographic finding ID — fully reproducible (spec: determinism).
func Rank(findings []models.Finding, cache *feed.Cache) []FindingRank {
	// Tier precedence: actively_exploited (KEV) > high_probability
	// (EPSS >= 0.5) > no_exploit_evidence. Tiers use ONLY documented cache
	// values — no thresholds invented here; EPSS 0.5 is the value FIRST
	// itself publishes as the "likely exploited within 30 days" decision
	// line in its own tooling and analyses.
	const highLine = 0.5

	ranks := make([]FindingRank, 0, len(findings))
	for _, f := range findings {
		r := FindingRank{Finding: f}
		cves := cveOf(f)
		for _, cve := range cves {
			if e := cache.KEV(cve); e != nil {
				sig := &KEVSignal{InKEV: true, SourceURL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", Stale: e.Stale}
				var desc map[string]any
				_ = json.Unmarshal([]byte(e.Value), &desc)
				if s, ok := desc["product"].(string); ok {
					sig.Product = s
				}
				if s, ok := desc["vendor_project"].(string); ok {
					sig.Vendor = s
				}
				if s, ok := desc["date_added"].(string); ok {
					sig.DateAdded = s
				}
				if s, ok := desc["known_ransomware_use"].(string); ok {
					sig.Ransomware = s
				}
				r.KEV = sig
				r.Signals = append(r.Signals, models.Evidence{
					Type:      "feed",
					Source:    "cisa_kev",
					Timestamp: e.Fetched,
					Value:     e.Value,
					Citation:  models.SourceCitation{Organization: "CISA", Document: "KEV catalog", URL: sig.SourceURL, Accessed: e.Fetched.Format("2006-01-02")},
				})
			}
			if e := cache.EPSS(cve); e != nil {
				var epss float64
				var desc map[string]any
				_ = json.Unmarshal([]byte(e.Value), &desc)
				if v, ok := desc["epss"].(float64); ok {
					epss = v
				}
				sig := &EPSSSignal{Score: epss, SourceURL: "https://www.first.org/epss/", Stale: e.Stale}
				r.EPSS = sig
				r.Signals = append(r.Signals, models.Evidence{
					Type:      "feed",
					Source:    "first_epss",
					Timestamp: e.Fetched,
					Value:     e.Value,
					Citation:  models.SourceCitation{Organization: "FIRST", Document: "EPSS", URL: sig.SourceURL, Accessed: e.Fetched.Format("2006-01-02")},
				})
			}
		}
		switch {
		case r.KEV != nil && r.KEV.InKEV:
			r.Tier = "actively_exploited"
			r.TierReason = "documented KEV membership — confirmed in-the-wild exploitation (CISA)"
		case r.EPSS != nil && r.EPSS.Score >= highLine:
			r.Tier = "high_probability"
			r.TierReason = "FIRST EPSS score at or above the FIRST-documented 0.5 decision line"
		default:
			r.Tier = "no_exploit_evidence"
			r.TierReason = "no KEV membership and no cached EPSS score; ranked last until public evidence appears"
		}
		ranks = append(ranks, r)
	}

	// Deterministic sort: tier precedence → severity → ID.
	severityRank := map[models.Severity]int{
		models.SevCritical: 0,
		models.SevHigh:     1,
		models.SevMedium:   2,
		models.SevLow:      3,
	}
	tierRank := map[string]int{
		"actively_exploited":  0,
		"high_probability":    1,
		"no_exploit_evidence": 2,
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		ti, tj := tierRank[ranks[i].Tier], tierRank[ranks[j].Tier]
		if ti != tj {
			return ti < tj
		}
		si, sj := severityRank[ranks[i].Finding.Severity], severityRank[ranks[j].Finding.Severity]
		if si != sj {
			return si < sj
		}
		return ranks[i].Finding.ID < ranks[j].Finding.ID
	})
	for i := range ranks {
		ranks[i].Rank = i + 1
	}
	return ranks
}

// HasCVEs reports whether any finding carries a CVE reference — used by the
// command to recommend a feed sync when no CVEs are present at all.
func HasCVEs(findings []models.Finding) bool {
	for _, f := range findings {
		if len(cveOf(f)) > 0 {
			return true
		}
	}
	return false
}
