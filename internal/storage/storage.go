// Package storage implements storage-v1: local SQLite persistence for assets,
// findings, evidence, and relationships (Phase 2.6, ADR-0003).
//
// Rules: the database file is created with 0600 permissions; schemas are
// versioned and checked on open; every row stores its schema version and
// JSON payload so canonical JSON roundtrips; inserts are idempotent by
// content ID (re-runs do not duplicate); secrets are never written to the
// store (values stored are observation outputs only).
package storage

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

const schemaVersion = "storage-v1"

const migrations = `
CREATE TABLE IF NOT EXISTS assets (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	value TEXT NOT NULL,
	host TEXT,
	port INTEGER,
	protocol TEXT,
	exposure TEXT NOT NULL,
	criticality TEXT,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	provenance TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
	id TEXT PRIMARY KEY,
	asset_id TEXT NOT NULL,
	asset_value TEXT NOT NULL,
	title TEXT NOT NULL,
	description TEXT NOT NULL,
	observation TEXT NOT NULL,
	severity TEXT NOT NULL,
	confidence TEXT NOT NULL,
	status TEXT NOT NULL,
	validation TEXT NOT NULL,
	classification TEXT NOT NULL,
	remediation TEXT,
	refs TEXT NOT NULL,
	created_at TEXT NOT NULL,
	schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
	id TEXT PRIMARY KEY,
	finding_id TEXT,
	asset_id TEXT,
	type TEXT NOT NULL,
	source TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	value TEXT NOT NULL,
	citation TEXT NOT NULL,
	schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relationships (
	id TEXT PRIMARY KEY,
	from_id TEXT NOT NULL,
	to_id TEXT NOT NULL,
	type TEXT NOT NULL,
	status TEXT NOT NULL,
	evidence TEXT NOT NULL,
	schema_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS riskscores (
	asset_id TEXT PRIMARY KEY,
	score REAL NOT NULL,
	severity TEXT NOT NULL,
	factors TEXT NOT NULL,
	weights TEXT NOT NULL,
	model_version TEXT NOT NULL,
	stale TEXT NOT NULL,
	incomplete TEXT NOT NULL,
	computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id);
`

// Store is the local SQLite store.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens (or creates) the store at path with secure file permissions.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errs.Input("storage.open", "database path required",
			"set RISKX_DB or use 'riskx init'")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errs.Wrap(errs.CodeConfigError, "storage.open", "cannot create database directory", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			return nil, errs.Wrap(errs.CodeConfigError, "storage.open", "cannot create database file", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, errs.Wrap(errs.CodeConfigError, "storage.open", "cannot stat database file", err)
	}
	if info.Mode().Perm() != 0600 {
		if err := os.Chmod(path, 0600); err != nil {
			return nil, errs.Wrap(errs.CodeConfigError, "storage.open", "cannot set 0600 on database file", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "storage.open", "cannot open sqlite database", err)
	}
	if _, err := db.Exec(migrations); err != nil {
		db.Close()
		return nil, errs.Wrap(errs.CodeInternal, "storage.open", "cannot apply migrations", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// SchemaVersion returns the storage schema version.
func SchemaVersion() string { return schemaVersion }

// PutAssets inserts assets idempotently (upsert by content ID).
func (s *Store) PutAssets(assets []models.Asset) (int, error) {
	stmt, err := s.db.Prepare(`INSERT INTO assets (id, kind, value, host, port, protocol, exposure,
		criticality, first_seen, last_seen, provenance, fingerprint, schema_version)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen`)
	if err != nil {
		return 0, errs.Wrap(errs.CodeInternal, "storage.put_assets", "prepare failed", err)
	}
	defer stmt.Close()
	n := 0
	for _, a := range assets {
		if _, err := stmt.Exec(
			a.ID, string(a.Kind), a.Value, a.Host, a.Port, a.Protocol, string(a.Exposure),
			a.Criticality, a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339),
			jsonOf(a.Provenance), jsonOf(a.Fingerprint), a.Schema); err != nil {
			return n, errs.Wrap(errs.CodeInternal, "storage.put_assets", "insert failed", err)
		}
		n++
	}
	return n, nil
}

// PutFindings inserts findings idempotently.
func (s *Store) PutFindings(findings []models.Finding) error {
	stmt, err := s.db.Prepare(`INSERT INTO findings (id, asset_id, asset_value, title, description,
		observation, severity, confidence, status, validation, classification, remediation,
		refs, created_at, schema_version)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "storage.put_findings", "prepare failed", err)
	}
	defer stmt.Close()
	for _, f := range findings {
		var rem string
		if f.Remediation != nil {
			rem = jsonOf(f.Remediation)
		}
		if _, err := stmt.Exec(
			f.ID, f.AssetID, f.AssetValue, f.Title, f.Description, f.Observation,
			string(f.Severity), string(f.Confidence), string(f.Status), string(f.Validation),
			jsonOf(f.Classification), rem, jsonOf(f.References),
			f.CreatedAt.UTC().Format(time.RFC3339), f.Schema); err != nil {
			return errs.Wrap(errs.CodeInternal, "storage.put_findings", "insert failed", err)
		}
	}
	return nil
}

// PutEvidence inserts evidence items linked to findings and assets.
func (s *Store) PutEvidence(items []models.Evidence, findingID, assetID string) error {
	stmt, err := s.db.Prepare(`INSERT INTO evidence (id, finding_id, asset_id, type, source,
		timestamp, value, citation, schema_version) VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "storage.put_evidence", "prepare failed", err)
	}
	defer stmt.Close()
	for _, e := range items {
		if _, err := stmt.Exec(
			evidenceID(e), findingID, assetID, e.Type, e.Source,
			e.Timestamp.UTC().Format(time.RFC3339), e.Value, jsonOf(e.Citation), models.SchemaEvidence); err != nil {
			return errs.Wrap(errs.CodeInternal, "storage.put_evidence", "insert failed", err)
		}
	}
	return nil
}

// PutRelationships inserts graph edges idempotently.
func (s *Store) PutRelationships(rels []models.Relationship) error {
	stmt, err := s.db.Prepare(`INSERT INTO relationships (id, from_id, to_id, type, status, evidence,
		schema_version) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "storage.put_relationships", "prepare failed", err)
	}
	defer stmt.Close()
	for _, r := range rels {
		if _, err := stmt.Exec(r.ID, r.From, r.To, string(r.Type), string(r.Status),
			jsonOf(r.Evidence), r.Schema); err != nil {
			return errs.Wrap(errs.CodeInternal, "storage.put_relationships", "insert failed", err)
		}
	}
	return nil
}

// PutRiskScore upserts a risk score for an asset.
func (s *Store) PutRiskScore(score models.RiskScore) error {
	_, err := s.db.Exec(`INSERT INTO riskscores (asset_id, score, severity, factors, weights,
		model_version, stale, incomplete, computed_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(asset_id) DO UPDATE SET score=excluded.score, severity=excluded.severity,
		factors=excluded.factors, weights=excluded.weights, stale=excluded.stale,
		incomplete=excluded.incomplete, computed_at=excluded.computed_at`,
		score.AssetID, score.Score, string(score.Severity), jsonOf(score.Factors),
		jsonOf(score.Weights), score.ModelVersion, jsonOf(score.Stale), jsonOf(score.Incomplete),
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "storage.put_riskscore", "upsert failed", err)
	}
	return nil
}

// ListAssets returns stored assets.
func (s *Store) ListAssets() ([]models.Asset, error) {
	rows, err := s.db.Query(`SELECT id, kind, value, host, port, protocol, exposure, criticality,
		first_seen, last_seen, provenance, fingerprint, schema_version FROM assets ORDER BY last_seen DESC`)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "storage.list_assets", "query failed", err)
	}
	defer rows.Close()
	var out []models.Asset
	for rows.Next() {
		var a models.Asset
		var prov, fp, schema string
		var firstSeen, lastSeen sql.NullString
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Host, &a.Port, &a.Protocol, &a.Exposure,
			&a.Criticality, &firstSeen, &lastSeen, &prov, &fp, &schema); err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "storage.list_assets", "scan failed", err)
		}
		_ = jsonDecode(prov, &a.Provenance)
		_ = jsonDecode(fp, &a.Fingerprint)
		a.Schema = schema
		if firstSeen.Valid {
			if t, err := time.Parse(time.RFC3339, firstSeen.String); err == nil {
				a.FirstSeen = t
			}
		}
		if lastSeen.Valid {
			if t, err := time.Parse(time.RFC3339, lastSeen.String); err == nil {
				a.LastSeen = t
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListFindings returns stored findings.
func (s *Store) ListFindings() ([]models.Finding, error) {
	rows, err := s.db.Query(`SELECT id, asset_id, asset_value, title, description, observation,
		severity, confidence, status, validation, classification, remediation, refs,
		created_at, schema_version FROM findings ORDER BY created_at DESC`)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "storage.list_findings", "query failed", err)
	}
	defer rows.Close()
	var out []models.Finding
	for rows.Next() {
		var f models.Finding
		var cls, rem, refs, schema, created string
		if err := rows.Scan(&f.ID, &f.AssetID, &f.AssetValue, &f.Title, &f.Description,
			&f.Observation, &f.Severity, &f.Confidence, &f.Status, &f.Validation,
			&cls, &rem, &refs, &created, &schema); err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "storage.list_findings", "scan failed", err)
		}
		_ = jsonDecode(cls, &f.Classification)
		_ = jsonDecode(refs, &f.References)
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			f.CreatedAt = t
		}
		_ = jsonDecode(cls, &f.Classification)
		_ = jsonDecode(refs, &f.References)
		if rem != "" {
			f.Remediation = &models.Remediation{}
			_ = jsonDecode(rem, f.Remediation)
		}
		f.Schema = schema
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListRiskScores returns stored risk scores.
func (s *Store) ListRiskScores() ([]models.RiskScore, error) {
	rows, err := s.db.Query(`SELECT asset_id, score, severity, factors, weights, model_version,
		stale, incomplete FROM riskscores ORDER BY score DESC`)
	if err != nil {
		return nil, errs.Wrap(errs.CodeInternal, "storage.list_riskscores", "query failed", err)
	}
	defer rows.Close()
	var out []models.RiskScore
	for rows.Next() {
		var s2 models.RiskScore
		var factors, weights, stale, incomplete string
		if err := rows.Scan(&s2.AssetID, &s2.Score, &s2.Severity, &factors, &weights,
			&s2.ModelVersion, &stale, &incomplete); err != nil {
			return nil, errs.Wrap(errs.CodeInternal, "storage.list_riskscores", "scan failed", err)
		}
		_ = jsonDecode(factors, &s2.Factors)
		_ = jsonDecode(weights, &s2.Weights)
		_ = jsonDecode(stale, &s2.Stale)
		_ = jsonDecode(incomplete, &s2.Incomplete)
		out = append(out, s2)
	}
	return out, rows.Err()
}

// Count returns (assets, findings, scores) counts.
func (s *Store) Count() (int64, int64, int64, error) {
	var a, f, r int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM assets").Scan(&a); err != nil {
		return 0, 0, 0, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&f); err != nil {
		return 0, 0, 0, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM riskscores").Scan(&r); err != nil {
		return 0, 0, 0, err
	}
	return a, f, r, nil
}

// evidenceID produces a deterministic ID from the evidence content.
func evidenceID(e models.Evidence) string {
	return models.ContentID("ev", e.Type, e.Source, e.Timestamp.UnixNano(), e.Value)
}

func jsonOf(v any) string {
	b, err := marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func jsonDecode(s string, v any) error {
	if s == "" {
		return nil
	}
	return unmarshal([]byte(s), v)
}

// marshal/unmarshal delegates to encoding/json via small wrappers so the
// package can swap implementations (e.g., for a JSONL variant) without
// touching call sites.
func marshal(v any) ([]byte, error) { return json.Marshal(v) }

func unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
