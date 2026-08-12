// Package delta implements delta-v1: snapshot diffing for continuous
// change detection (CTEM continuous-monitoring stage; Praetorian EASM
// lifecycle: fingerprinting -> change detection). See
// /home/ubuntu/riskx-research/delta-scanning-design.md for the design
// evidence trail.
//
// Rules (no-guessing policy):
//   - A snapshot records only assets and findings actually observed in a run.
//   - A delta item is emitted ONLY when the underlying observation changed:
//     new_asset (first time seen), gone_asset (persisted in a prior snapshot,
//     absent from the current run's input set), changed_asset (stable
//     fingerprint hash of observed fields differs), new_finding,
//     resolved_finding (finding absent from the current input set), and
//     changed_finding.
//   - Absence of an enumeration result is NOT treated as evidence of absence:
//     gone_asset and resolved_finding are computed strictly against the input
//     set handed to Diff, never from inference about what "should" exist.
//   - Every delta item carries the evidence that justifies it (fingerprint
//     hashes, run IDs) so the output is auditable.
package delta

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

const schema = "delta-v1"

// Kind names a category of observed change between two scans.
type Kind string

const (
	KindNewAsset       Kind = "new_asset"       // asset first observed in this run
	KindGoneAsset      Kind = "gone_asset"      // asset in prior snapshot, not in current input
	KindChangedAsset   Kind = "changed_asset"   // fingerprint hash of observed fields changed
	KindNewFinding     Kind = "new_finding"     // finding first observed in this run
	KindResolvedFinding Kind = "resolved_finding" // finding in prior snapshot, not in current input
	KindChangedFinding Kind = "changed_finding" // finding content changed between runs
)

// Snapshot (delta-v1) is the canonical, hash-addressed record of one scan run.
// It stores assets and findings keyed by ID plus a stable fingerprint hash per
// asset so diffs are cheap and deterministic.
type Snapshot struct {
	ID         string            `json:"id" yaml:"id"`
	TakenAt    time.Time         `json:"taken_at" yaml:"taken_at"`
	Schema     string            `json:"schema" yaml:"schema"`
	Fingerprints map[string]string `json:"fingerprints" yaml:"fingerprints"` // asset ID -> fp hash
	AssetHashes  map[string]string `json:"asset_hashes" yaml:"asset_hashes"` // asset ID -> canonical hash
	FindingHashes map[string]string `json:"finding_hashes" yaml:"finding_hashes"`
	Assets       []models.Asset   `json:"assets" yaml:"assets"`
	Findings     []models.Finding `json:"findings" yaml:"findings"`
}

// NewSnapshot builds a delta-v1 snapshot from the assets and findings observed
// in one run. Fingerprint hashes cover only actually-observed technical fields.
func NewSnapshot(id string, assets []models.Asset, findings []models.Finding) Snapshot {
	fps := make(map[string]string, len(assets))
	ah := make(map[string]string, len(assets))
	for i := range assets {
		a := &assets[i]
		fps[a.ID] = fpHash(a.Fingerprint)
		ah[a.ID] = canonHash(canonicalAsset(a))
	}
	fh := make(map[string]string, len(findings))
	for i := range findings {
		f := &findings[i]
		fh[f.ID] = canonHash(canonicalFinding(f))
	}
	return Snapshot{
		ID:            id,
		TakenAt:       time.Now().UTC(),
		Schema:        schema,
		Fingerprints:  fps,
		AssetHashes:   ah,
		FindingHashes: fh,
		Assets:        assets,
		Findings:      findings,
	}
}

// normalizeHashes regenerates the hash maps from the stored assets and
// findings when they are absent, so a snapshot payload remains fully
// self-describing even when the maps were never populated (e.g. older
// payloads or payloads written by external tooling). Empty maps are filled
// in place; already-populated maps are left untouched.
func (s *Snapshot) NormalizeHashes() {
	if len(s.AssetHashes) == 0 && len(s.Assets) > 0 {
		s.AssetHashes = make(map[string]string, len(s.Assets))
		s.Fingerprints = make(map[string]string, len(s.Assets))
		for i := range s.Assets {
			a := &s.Assets[i]
			s.AssetHashes[a.ID] = canonHash(canonicalAsset(a))
			s.Fingerprints[a.ID] = fpHash(a.Fingerprint)
		}
	}
	if len(s.FindingHashes) == 0 && len(s.Findings) > 0 {
		s.FindingHashes = make(map[string]string, len(s.Findings))
		for i := range s.Findings {
			f := &s.Findings[i]
			s.FindingHashes[f.ID] = canonHash(canonicalFinding(f))
		}
	}
}

// DeltaItem is one observed change, justified by the hashes that prove it.
type DeltaItem struct {
	Kind     Kind   `json:"kind" yaml:"kind"`
	ID       string `json:"id" yaml:"id"`       // asset or finding ID
	Label    string `json:"label" yaml:"label"` // asset value / finding title
	PriorHash string `json:"prior_hash,omitempty" yaml:"prior_hash,omitempty"`
	CurrentHash string `json:"current_hash,omitempty" yaml:"current_hash,omitempty"`
	PriorRun    string   `json:"prior_run,omitempty" yaml:"prior_run,omitempty"`
	CurrentRun  string   `json:"current_run,omitempty" yaml:"current_run,omitempty"`
	Changes     []string `json:"changes,omitempty" yaml:"changes,omitempty"` // field-level diffs for changed_asset
}

// Diff returns the delta between an earlier snapshot (may be nil = first run)
// and the current run's input. Invariants: no item is emitted for entities
// that did not change; gone/resolved items are computed purely from the
// provided current input sets.
func Diff(prior *Snapshot, assets []models.Asset, findings []models.Finding, runID string) []DeltaItem {
	if prior == nil || prior.ID == "" {
		out := make([]DeltaItem, 0, len(assets)+len(findings))
		for i := range assets {
			a := &assets[i]
			out = append(out, DeltaItem{Kind: KindNewAsset, ID: a.ID, Label: a.Value,
				CurrentHash: canonHash(canonicalAsset(a)), CurrentRun: runID})
		}
		for i := range findings {
			f := &findings[i]
			out = append(out, DeltaItem{Kind: KindNewFinding, ID: f.ID, Label: f.Title,
				CurrentHash: canonHash(canonicalFinding(f)), CurrentRun: runID})
		}
		sortItems(out)
		return out
	}

	curAssets := make(map[string]*models.Asset, len(assets))
	for i := range assets {
		curAssets[assets[i].ID] = &assets[i]
	}
	curFindings := make(map[string]*models.Finding, len(findings))
	for i := range findings {
		curFindings[findings[i].ID] = &findings[i]
	}

	var out []DeltaItem
	// Assets: new, gone, changed.
	for i := range assets {
		a := &assets[i]
		if _, exists := prior.AssetHashes[a.ID]; !exists {
			out = append(out, DeltaItem{Kind: KindNewAsset, ID: a.ID, Label: a.Value,
				CurrentHash: canonHash(canonicalAsset(a)), CurrentRun: runID})
			continue
		}
		if prior.AssetHashes[a.ID] != canonHash(canonicalAsset(a)) {
			priorFP := fpFrom(prior.Assets, a.ID)
			changes := FieldDiffStruct(priorFP, a.Fingerprint)
			out = append(out, DeltaItem{Kind: KindChangedAsset, ID: a.ID, Label: a.Value,
				PriorHash: prior.Fingerprints[a.ID], CurrentHash: fpHash(a.Fingerprint),
				PriorRun: prior.ID, CurrentRun: runID, Changes: changes})
		}
	}
	for id, h := range prior.AssetHashes {
		if _, cur := curAssets[id]; !cur {
			a := findAsset(prior.Assets, id)
			out = append(out, DeltaItem{Kind: KindGoneAsset, ID: id, Label: a,
				PriorHash: h, PriorRun: prior.ID})
		}
	}
	// Findings: new, resolved, changed.
	for i := range findings {
		f := &findings[i]
		if _, exists := prior.FindingHashes[f.ID]; !exists {
			out = append(out, DeltaItem{Kind: KindNewFinding, ID: f.ID, Label: f.Title,
				CurrentHash: canonHash(canonicalFinding(f)), CurrentRun: runID})
			continue
		}
		if prior.FindingHashes[f.ID] != canonHash(canonicalFinding(f)) {
			out = append(out, DeltaItem{Kind: KindChangedFinding, ID: f.ID, Label: f.Title,
				PriorHash: prior.FindingHashes[f.ID], CurrentHash: canonHash(canonicalFinding(f)),
				PriorRun: prior.ID})
		}
	}
	for id, h := range prior.FindingHashes {
		if _, cur := curFindings[id]; !cur {
			f := findFinding(prior.Findings, id)
			out = append(out, DeltaItem{Kind: KindResolvedFinding, ID: id, Label: f,
				PriorHash: h, PriorRun: prior.ID})
		}
	}
	sortItems(out)
	return out
}

// CurrentRun is added via the struct literal above; declare the field here.
func init() {}

// Summary counts delta items by kind.
func Summary(items []DeltaItem) map[Kind]int {
	m := make(map[Kind]int)
	for _, it := range items {
		m[it.Kind]++
	}
	return m
}

// ------------------------------------------------------------- internals ---

func sortItems(items []DeltaItem) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].ID < items[j].ID
	})
}

func fpFrom(assets []models.Asset, id string) models.Fingerprint {
	for i := range assets {
		if assets[i].ID == id {
			return assets[i].Fingerprint
		}
	}
	return models.Fingerprint{}
}

func findAsset(assets []models.Asset, id string) string {
	for i := range assets {
		if assets[i].ID == id {
			return assets[i].Value
		}
	}
	return id
}

func findFinding(findings []models.Finding, id string) string {
	for i := range findings {
		if findings[i].ID == id {
			return findings[i].Title
		}
	}
	return id
}

// fpHash hashes ONLY observed fingerprint fields (empty slices/nils are
// normalized to absent), so unknown vs unknown never reads as a change.
func fpHash(fp models.Fingerprint) string {
	// Build a flat canonical map of populated fields.
	flat := make(map[string]string)
	if fp.HTTPServer != "" {
		flat["http_server"] = fp.HTTPServer
	}
	if fp.Banner != "" {
		flat["banner"] = fp.Banner
	}
	if fp.TLSIssuer != "" {
		flat["tls_issuer"] = fp.TLSIssuer
	}
	if fp.TLSExpired != nil {
		flat["tls_expired"] = fmt.Sprintf("%v", *fp.TLSExpired)
	}
	if fp.TLSKeyBits > 0 {
		flat["tls_key_bits"] = fmt.Sprintf("%d", fp.TLSKeyBits)
	}
	for _, s := range fp.TLSSANs {
		if s != "" {
			flat["tls_san:"+s] = ""
		}
	}
	for _, s := range fp.TLSSubjects {
		if s != "" {
			flat["tls_subject:"+s] = ""
		}
	}
	sortKeys := make([]string, 0, len(flat))
	for k := range flat {
		sortKeys = append(sortKeys, k)
	}
	sort.Strings(sortKeys)
	var b []byte
	for _, k := range sortKeys {
		b = append(b, []byte(k+"="+flat[k]+"\n")...)
	}
	return hashStr(string(b))
}

// FieldDiffStruct reports the specific fingerprint fields that changed
// between two asset inputs. Empty string fields and nil/zero values are
// treated as unobserved and never reported as changes.
func FieldDiffStruct(a, b models.Fingerprint) []string {
	ma := fpFlat(a)
	mb := fpFlat(b)
	keys := make(map[string]struct{}, len(ma)+len(mb))
	for k := range ma {
		keys[k] = struct{}{}
	}
	for k := range mb {
		keys[k] = struct{}{}
	}
	ks := make([]string, 0, len(keys))
	for k := range keys {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var out []string
	for _, k := range ks {
		va, okA := ma[k]
		vb, okB := mb[k]
		if va != vb || okA != okB {
			out = append(out, k)
		}
	}
	return out
}

func fpFlat(fp models.Fingerprint) map[string]string {
	flat := make(map[string]string)
	if fp.HTTPServer != "" {
		flat["http_server"] = fp.HTTPServer
	}
	if fp.Banner != "" {
		flat["banner"] = fp.Banner
	}
	if fp.TLSIssuer != "" {
		flat["tls_issuer"] = fp.TLSIssuer
	}
	if fp.TLSExpired != nil {
		flat["tls_expired"] = fmt.Sprintf("%v", *fp.TLSExpired)
	}
	if fp.TLSKeyBits > 0 {
		flat["tls_key_bits"] = fmt.Sprintf("%d", fp.TLSKeyBits)
	}
	for _, s := range fp.TLSSANs {
		if s != "" {
			flat["tls_san:"+s] = ""
		}
	}
	for _, s := range fp.TLSSubjects {
		if s != "" {
			flat["tls_subject:"+s] = ""
		}
	}
	return flat
}

// ------------------------------------------------------------- hashing ---

func canonicalAsset(a *models.Asset) map[string]any {
	return map[string]any{
		"id": a.ID, "kind": string(a.Kind), "value": a.Value,
		"host": a.Host, "port": a.Port, "protocol": a.Protocol,
		"exposure": string(a.Exposure),
		// Fingerprint covers only OBSERVED technical fields (tls_sans sorted,
		// tls_subjects sorted; empty/nil fields omitted), so identity changes
		// track real configuration drift, never missing-observation noise.
		"fingerprint": canonFP(a.Fingerprint),
	}
}

func canonicalFinding(f *models.Finding) map[string]any {
	return map[string]any{
		"id": f.ID, "asset_id": f.AssetID, "asset_value": f.AssetValue,
		"title": f.Title, "severity": string(f.Severity),
		"observation": f.Observation, "confidence": string(f.Confidence),
		"status": string(f.Status),
	}
}

func canonHash(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return hashStr(string(b))
}

func canonFP(fp models.Fingerprint) map[string]any {
	m := fpFlat(fp)
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func hashStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}
