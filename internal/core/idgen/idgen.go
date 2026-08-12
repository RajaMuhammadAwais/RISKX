// Package idgen generates stable, content-addressed identifiers.
//
// IDs are deterministic hashes of content so that the same evidence always
// yields the same ID across runs (reproducibility, spec §27, §43). Finding IDs
// carry the RISKX- prefix per the evidence-system example (spec §19).
package idgen

import (
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// FindingID returns a stable RISKX-<hash> finding identifier.
func FindingID(parts ...any) string {
	return "RISKX-" + short(models.ContentID("finding", parts...))
}

// AssetID returns a stable asset identifier.
func AssetID(parts ...any) string {
	return models.ContentID("asset", parts...)
}

// RelationshipID returns a stable edge identifier.
func RelationshipID(parts ...any) string {
	return models.ContentID("rel", parts...)
}

// EvidenceID returns a stable evidence-item identifier.
func EvidenceID(parts ...any) string {
	return models.ContentID("ev", parts...)
}

// SnapshotID returns a stable snapshot identifier derived from the run's
// discovered content so identical runs produce identical snapshot IDs
// (reproducibility, spec §27, §43).
func SnapshotID(parts ...any) string {
	return "snap-" + short(models.ContentID("snap", parts...))
}

// short truncates a hex content ID to 16 characters, keeping determinism.
func short(s string) string {
	const n = 16
	if len(s) > n {
		return s[:n]
	}
	return s
}
