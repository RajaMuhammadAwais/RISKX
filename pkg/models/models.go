// Package models defines the canonical, versioned RISKX data model.
//
// Schema versions (spec §45): asset-v1, finding-v1, evidence-v1.
// Design constraints:
//   - Every security artifact carries evidence (spec §19).
//   - Relationships carry an evidence status: Observed/Inferred/Potential/Validated
//     (spec §13). Inferred is never presented as confirmed.
//   - FACT / INFERENCE / RECOMMENDATION are separated in the data model (spec §20).
//   - No field may silently carry guessed data: detection without evidence reports
//     ConfidenceInsufficient (spec §15).
package models

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion identifiers for the canonical model.
const (
	SchemaAsset    = "asset-v1"
	SchemaFinding  = "finding-v1"
	SchemaEvidence = "evidence-v1"
)

// AssetKind enumerates asset supertype kinds (spec §9).
type AssetKind string

const (
	KindHost          AssetKind = "host"
	KindIP            AssetKind = "ip"
	KindDomain        AssetKind = "domain"
	KindService       AssetKind = "service"
	KindApplication   AssetKind = "application"
	KindAPI           AssetKind = "api"
	KindCloudResource AssetKind = "cloud_resource"
	KindContainer     AssetKind = "container"
	KindK8sResource   AssetKind = "k8s_resource"
	KindRepository    AssetKind = "repository"
	KindAIEndpoint    AssetKind = "ai_endpoint"
	KindMCPEndpoint   AssetKind = "mcp_endpoint"
	KindAgent         AssetKind = "agent"
	KindMCPServer     AssetKind = "mcp_server"
	KindIdentity      AssetKind = "identity"
)

// EvidenceStatus describes how strongly a relationship or fact is backed
// (spec §13). Statuses MUST be rendered distinctly; Inferred is never
// presented as a confirmed attack or confirmed exposure.
type EvidenceStatus string

const (
	StatusObserved   EvidenceStatus = "observed"   // directly measured in this scan
	StatusInferred   EvidenceStatus = "inferred"   // plausible from evidence, not directly measured
	StatusPotential  EvidenceStatus = "potential"  // theoretically possible, no evidence yet
	StatusValidated  EvidenceStatus = "validated"  // confirmed via safe validation mode
)

// Confidence describes overall confidence in a finding or detection result.
type Confidence string

const (
	ConfidenceHigh         Confidence = "high"
	ConfidenceMedium       Confidence = "medium"
	ConfidenceLow          Confidence = "low"
	ConfidenceInsufficient Confidence = "insufficient" // no evidence; must NOT be guessed (spec §15)
)

// ExposureLevel describes network exposure of an asset.
type ExposureLevel string

const (
	ExposureInternet ExposureLevel = "internet"
	ExposureInternal ExposureLevel = "internal"
	ExposureUnknown  ExposureLevel = "unknown" // not absence of exposure: visibility incomplete (spec §48)
)

// Asset is the discovery supertype: a thing that can be exposed, assessed, or
// related to other assets (spec §9). Identity carries provenance so that every
// inventory entry can answer "how do you know this asset exists?"
type Asset struct {
	ID          string      `json:"id" yaml:"id"`
	Kind        AssetKind   `json:"kind" yaml:"kind"`
	Value       string      `json:"value" yaml:"value"` // canonical representation (FQDN, IP, URL...)
	Host        string      `json:"host,omitempty" yaml:"host,omitempty"`
	Port        int         `json:"port,omitempty" yaml:"port,omitempty"`
	Protocol    string      `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Exposure    ExposureLevel `json:"exposure" yaml:"exposure"`
	Criticality string      `json:"criticality,omitempty" yaml:"criticality,omitempty"`
	FirstSeen   time.Time   `json:"first_seen" yaml:"first_seen"`
	LastSeen    time.Time   `json:"last_seen" yaml:"last_seen"`
	Provenance  Provenance  `json:"provenance" yaml:"provenance"`
	Fingerprint Fingerprint `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Schema      string      `json:"schema" yaml:"schema"`
}

// Provenance records how the asset was discovered (spec §9: detection ≠
// identification ≠ fingerprinting). Method names the technique; Source the
// infrastructure; Timestamp when; Confidence how certain.
type Provenance struct {
	Source     string     `json:"source" yaml:"source"`
	Method     string     `json:"method" yaml:"method"`
	Timestamp  time.Time  `json:"timestamp" yaml:"timestamp"`
	Confidence Confidence `json:"confidence" yaml:"confidence"`
}

// Fingerprint records observed technical attributes. Only values actually
// observed are populated; unknown fields stay empty rather than guessed.
type Fingerprint struct {
	HTTPServer    string   `json:"http_server,omitempty" yaml:"http_server,omitempty"`
	TLSSubjects   []string `json:"tls_subjects,omitempty" yaml:"tls_subjects,omitempty"`
	TLSSANs       []string `json:"tls_sans,omitempty" yaml:"tls_sans,omitempty"`
	TLSIssuer     string   `json:"tls_issuer,omitempty" yaml:"tls_issuer,omitempty"`
	TLSExpired    *bool    `json:"tls_expired,omitempty" yaml:"tls_expired,omitempty"`
	TLSKeyBits    int      `json:"tls_key_bits,omitempty" yaml:"tls_key_bits,omitempty"`
	OpenPorts     []int    `json:"open_ports,omitempty" yaml:"open_ports,omitempty"`
	Banner        string   `json:"banner,omitempty" yaml:"banner,omitempty"`
	RegisteredOrg string   `json:"registered_org,omitempty" yaml:"registered_org,omitempty"`
	Registrar     string   `json:"registrar,omitempty" yaml:"registrar,omitempty"`
}

// Relationship connects assets or identities (spec §13). Edge status is the
// core attack-graph datum.
type Relationship struct {
	ID     string         `json:"id" yaml:"id"`
	From   string         `json:"from" yaml:"from"` // asset/identity ID
	To     string         `json:"to" yaml:"to"`
	Type   RelationshipType `json:"type" yaml:"type"`
	Status EvidenceStatus `json:"status" yaml:"status"`
	Evidence []Evidence   `json:"evidence" yaml:"evidence"`
	Schema string         `json:"schema" yaml:"schema"`
}

// RelationshipType enumerates edge semantics.
type RelationshipType string

const (
	RelExposes      RelationshipType = "exposes"
	RelRuns         RelationshipType = "runs"
	RelAffectedBy   RelationshipType = "affected_by"
	RelAccessibleBy RelationshipType = "accessible_by"
	RelConnectedTo  RelationshipType = "connected_to"
	RelParticipates RelationshipType = "participates_in"
)

// Classification holds taxonomy references for a finding, each versioned.
type Classification struct {
	CWE             string   `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	OWASPTop10      string   `json:"owasp_top10_2025,omitempty" yaml:"owasp_top10_2025,omitempty"`
	OWASPMCPTop10   []string `json:"owasp_mcp_top10,omitempty" yaml:"owasp_mcp_top10,omitempty"`
	ATTACKTechnique string   `json:"attack_technique,omitempty" yaml:"attack_technique,omitempty"` // e.g. "T1190" with version noted in ATT&CKVersion
	ATTACKVersion   string   `json:"attack_version,omitempty" yaml:"attack_version,omitempty"`
}

// Finding is the mandatory evidence-backed security finding (spec §19).
// It separates FACT (observation + evidence), INFERENCE (confidence/status),
// and RECOMMENDATION (spec §20) — Remediation is attached separately.
type Finding struct {
	ID             string            `json:"finding_id" yaml:"finding_id"`
	Schema         string            `json:"schema" yaml:"schema"`
	AssetID        string            `json:"asset_id" yaml:"asset_id"`
	AssetValue     string            `json:"asset_value" yaml:"asset_value"`
	Title          string            `json:"title" yaml:"title"`
	Description    string            `json:"description" yaml:"description"`
	Observation    string            `json:"observation" yaml:"observation"`      // FACT
	Evidence       []Evidence        `json:"evidence" yaml:"evidence"`            // FACT backing
	Severity       Severity          `json:"severity" yaml:"severity"`
	Confidence     Confidence        `json:"confidence" yaml:"confidence"`        // INFERENCE
	Status         EvidenceStatus    `json:"status" yaml:"status"`                // INFERENCE
	Validation     ValidationStatus  `json:"validation" yaml:"validation"`
	Classification Classification    `json:"classification,omitempty" yaml:"classification,omitempty"`
	Remediation    *Remediation      `json:"remediation,omitempty" yaml:"remediation,omitempty"` // RECOMMENDATION
	Suppression    *Suppression      `json:"suppression,omitempty" yaml:"suppression,omitempty"`
	References     []string          `json:"references,omitempty" yaml:"references,omitempty"`
	CreatedAt      time.Time         `json:"created_at" yaml:"created_at"`
}

// Severity is a CVSS-independent reporting severity band for findings.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// ValidationStatus tracks the Validate stage of the CTEM lifecycle per finding
// (spec §8, §30).
type ValidationStatus string

const (
	ValidationUnvalidated ValidationStatus = "unvalidated"
	ValidationPending     ValidationStatus = "pending"
	ValidationValidated   ValidationStatus = "validated"
	ValidationFailed      ValidationStatus = "failed"
)

// Suppression records an explicit exception with owner and expiration.
// Permanent silent suppression is prohibited (spec §30).
type Suppression struct {
	Reason    string    `json:"reason" yaml:"reason"`
	Owner     string    `json:"owner" yaml:"owner"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
	Expired   bool      `json:"expired" yaml:"expired"`
}

// IsActive reports whether the suppression currently applies.
func (s Suppression) IsActive(now time.Time) bool {
	if s.Expired {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// Remediation is the recommendation layer; never presented as fact (spec §20, §35).
type Remediation struct {
	Problem      string   `json:"problem" yaml:"problem"`
	WhyItMatters string   `json:"why_it_matters" yaml:"why_it_matters"`
	Evidence     []string `json:"evidence_summary" yaml:"evidence_summary"`
	Fix          string   `json:"recommended_fix" yaml:"recommended_fix"`
	Verification string   `json:"verification_method" yaml:"verification_method"`
	Rollback     string   `json:"rollback_consideration" yaml:"rollback_consideration"`
}

// Vulnerability is the normalized, provenance-tagged vulnerability record
// produced by the intelligence pipeline (docs/research/vulnerability-intelligence.md).
type Vulnerability struct {
	ID                string            `json:"id" yaml:"id"` // CVE-YYYY-NNNNN or vendor advisory ID
	Sources           []SourceCitation  `json:"sources" yaml:"sources"`
	Title             string            `json:"title,omitempty" yaml:"title,omitempty"`
	Description       string            `json:"description,omitempty" yaml:"description,omitempty"`
	CVSSVector        string            `json:"cvss_vector,omitempty" yaml:"cvss_vector,omitempty"`
	CVSSBaseScore     float64           `json:"cvss_base_score,omitempty" yaml:"cvss_base_score,omitempty"`
	CVSSExploitScore  float64           `json:"cvss_exploit_score,omitempty" yaml:"cvss_exploit_score,omitempty"`
	EPSS              *EPSSReading      `json:"epss,omitempty" yaml:"epss,omitempty"`
	InKEV             bool              `json:"in_kev" yaml:"in_kev"`
	KEVDateAdded      string            `json:"kev_date_added,omitempty" yaml:"kev_date_added,omitempty"`
	CWE               string            `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	AffectedProducts  []AffectedProduct `json:"affected_products,omitempty" yaml:"affected_products,omitempty"`
	Published         string            `json:"published,omitempty" yaml:"published,omitempty"`
	Stale             bool              `json:"stale" yaml:"stale"` // feed data older than allowed freshness
	Schema            string            `json:"schema" yaml:"schema"`
}

// EPSSReading is a timestamped FIRST EPSS score (evidence, not a static property).
type EPSSReading struct {
	Score     float64 `json:"score" yaml:"score"`
	Percentile float64 `json:"percentile" yaml:"percentile"`
	Date      string  `json:"date" yaml:"date"`
	Stale     bool    `json:"stale" yaml:"stale"`
}

// AffectedProduct records vendor/project/product naming as returned by feeds.
type AffectedProduct struct {
	Vendor  string `json:"vendor" yaml:"vendor"`
	Product string `json:"product" yaml:"product"`
}

// SourceCitation is the mandatory in-project citation metadata (spec §44).
type SourceCitation struct {
	Organization string `json:"organization" yaml:"organization"`
	Document     string `json:"document" yaml:"document"`
	URL          string `json:"url" yaml:"url"`
	Accessed     string `json:"accessed" yaml:"accessed"` // YYYY-MM-DD
	Version      string `json:"version,omitempty" yaml:"version,omitempty"`
}

// Evidence is a single evidence item: the atomic fact unit (spec §19).
type Evidence struct {
	Type      string    `json:"type" yaml:"type"` // configuration|network|certificate|feed|document|...
	Source    string    `json:"source" yaml:"source"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Value     string    `json:"value" yaml:"value"`
	Citation  SourceCitation `json:"citation,omitempty" yaml:"citation,omitempty"`
}

// RiskScore is the deterministic risk-v1 output (docs/architecture/architecture-v1.md §4).
type RiskScore struct {
	AssetID    string            `json:"asset_id" yaml:"asset_id"`
	Score      float64           `json:"score" yaml:"score"`            // 0..100
	Severity   Severity          `json:"severity" yaml:"severity"`
	Factors    []RiskFactor      `json:"factors" yaml:"factors"`
	Weights    map[string]float64 `json:"weights" yaml:"weights"`
	Evidence   []Evidence        `json:"evidence" yaml:"evidence"`
	ModelVersion string          `json:"model_version" yaml:"model_version"` // risk-v1
	Stale      []string          `json:"stale_inputs,omitempty" yaml:"stale_inputs,omitempty"`
	Incomplete []string          `json:"incomplete_inputs,omitempty" yaml:"incomplete_inputs,omitempty"`
}

// RiskFactor is one named component of the risk score with its evidence.
type RiskFactor struct {
	Name      string    `json:"name" yaml:"name"`
	Weight    float64   `json:"weight" yaml:"weight"`
	Value     float64   `json:"value" yaml:"value"` // 0..1
	Evidence  []Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Citation  string    `json:"citation,omitempty" yaml:"citation,omitempty"`
}

// FeedStatus records per-feed freshness so that outputs never pretend stale
// data is current (spec §48).
type FeedStatus struct {
	Feed       string    `json:"feed" yaml:"feed"`
	LastFetch  time.Time `json:"last_fetch" yaml:"last_fetch"`
	LastUpdate string    `json:"last_update,omitempty" yaml:"last_update,omitempty"`
	Stale      bool      `json:"stale" yaml:"stale"`
	Visibility string    `json:"visibility,omitempty" yaml:"visibility,omitempty"` // e.g. "incomplete" on permission denied
	Error      string    `json:"error,omitempty" yaml:"error,omitempty"`
}

// ScanMetadata accompanies every command output (spec §44, §46).
type ScanMetadata struct {
	Tool         string         `json:"tool" yaml:"tool"`
	ToolVersion  string         `json:"tool_version" yaml:"tool_version"`
	RiskModel    string         `json:"risk_model" yaml:"risk_model"`
	AssetSchema  string         `json:"asset_schema" yaml:"asset_schema"`
	FindingSchema string        `json:"finding_schema" yaml:"finding_schema"`
	EvidenceSchema string       `json:"evidence_schema" yaml:"evidence_schema"`
	Mode         string         `json:"mode" yaml:"mode"`
	StartedAt    time.Time      `json:"started_at" yaml:"started_at"`
	FinishedAt   time.Time      `json:"finished_at" yaml:"finished_at"`
	Feeds        []FeedStatus   `json:"feeds,omitempty" yaml:"feeds,omitempty"`
	Attribution  []string       `json:"attribution,omitempty" yaml:"attribution,omitempty"`
}

// InKEV reports whether KEV membership evidence exists on this finding.
func (f Finding) InKEV() bool {
	for _, e := range f.Evidence {
		if e.Type == "kev" {
			return true
		}
	}
	return false
}

// ExposureLevel returns the highest exposure evidenced on this finding's
// evidence chain (internet > internal > unknown).
func (f Finding) ExposureLevel() ExposureLevel {
	best := ExposureUnknown
	for _, e := range f.Evidence {
		switch ExposureLevel(e.Type) {
		case ExposureInternet:
			return ExposureInternet
		case ExposureInternal:
			if best == ExposureUnknown {
				best = ExposureInternal
			}
		}
	}
	return best
}

// IsAdmin reports whether admin-exposure evidence exists on this finding.
func (f Finding) IsAdmin() bool {
	for _, e := range f.Evidence {
		if e.Type == "admin_panel_exposed" {
			return true
		}
	}
	return false
}

// ReferencesCVE reports whether the finding's references include the CVE.
func (f Finding) ReferencesCVE(cve string) bool {
	for _, ref := range f.References {
		if ref == cve {
			return true
		}
	}
	return false
}

// ContentID returns a stable, content-addressed identifier for an asset.
func ContentID(prefix string, parts ...any) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, p := range parts {
		if err := enc.Encode(p); err != nil {
			// sha256.Encoder never errors for the types we pass; panic would be
			// wrong here, so we fall back to a time-based unique suffix.
			return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
		}
	}
	return fmt.Sprintf("%s-%x", prefix, h.Sum(nil))
}
