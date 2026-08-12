package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

const testKey = "riskx-test-key-0000"

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "riskx.db")
	s, err := New(ServerConfig{
		Listen:    "127.0.0.1:0",
		Key:       testKey,
		StorePath: db,
		ReadTimeout: 5 * time.Second,
		Now:         func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, db
}

var fixedNow = time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)

func doGet(s *Server, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)
	return rr
}

func TestServerRefusesToStartWithoutKey(t *testing.T) {
	dir := t.TempDir()
	_, err := New(ServerConfig{
		Listen:      "127.0.0.1:0",
		Key:         "",
		StorePath:   filepath.Join(dir, "riskx.db"),
		ReadTimeout: 5 * time.Second,
		Now:         func() time.Time { return fixedNow },
	})
	if err == nil {
		t.Fatal("expected error without API key, got nil")
	}
}

func TestAuthMissingKey(t *testing.T) {
	s, _ := newTestServer(t)
	rr := doGet(s, "/health", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", rr.Code)
	}
	var body apiResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Status != "error" || body.Error == "" {
		t.Fatalf("expected error payload, got %+v", body)
	}
}

func TestAuthWrongKey(t *testing.T) {
	s, _ := newTestServer(t)
	rr := doGet(s, "/health", "wrong-key")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong key, got %d", rr.Code)
	}
}

func TestAuthValidKey(t *testing.T) {
	s, _ := newTestServer(t)
	rr := doGet(s, "/health", testKey)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestEndpoints(t *testing.T) {
	s, db := newTestServer(t)
	// Seed one asset and one finding into the store so listing endpoints are
	// exercised against real stored data.
	store, err := storage.Open(db)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	now := time.Now().UTC()
	assets := []models.Asset{{
		ID:    models.ContentID("asset", "host", "seed.example.com"),
		Kind:  models.KindHost, Value: "seed.example.com",
		Exposure:   models.ExposureInternet,
		FirstSeen:  now, LastSeen: now,
		Provenance: models.Provenance{Source: "test", Method: "seed"},
	}}
	if _, err := store.PutAssets(assets); err != nil {
		t.Fatalf("PutAssets: %v", err)
	}
	findings := []models.Finding{{
		ID: models.ContentID("finding", "t", "seed.example.com"), AssetID: assets[0].ID,
		AssetValue: "seed.example.com", Title: "t", Description: "d",
		Observation: "o", 		Severity: models.SevHigh, Confidence: models.ConfidenceHigh,
		Status: models.StatusPotential, Validation: models.ValidationPending,
		Classification: models.Classification{CWE: "CWE-0"}, References: []string{},
		CreatedAt: now, Schema: models.SchemaFinding,
	}}
	if err := store.PutFindings(findings); err != nil {
		t.Fatalf("PutFindings: %v", err)
	}

	cases := []struct {
		path       string
		wantStatus int
		wantCount  int
	}{
		{"/api/v1/assets", http.StatusOK, 1},
		{"/api/v1/findings", http.StatusOK, 1},
		{"/api/v1/findings?severity=high", http.StatusOK, 1},
		{"/api/v1/findings?severity=critical", http.StatusOK, 0},
		{"/api/v1/scores", http.StatusOK, 0},
		{"/api/v1/evidence", http.StatusOK, 0},
		{"/api/v1/evidence?finding=x", http.StatusOK, 0},
		{"/api/v1/relationships", http.StatusOK, 0},
		{"/api/v1/summary", http.StatusOK, 0},
	}
	for _, c := range cases {
		rr := doGet(s, c.path, testKey)
		if rr.Code != c.wantStatus {
			t.Errorf("%s: status %d want %d: %s", c.path, rr.Code, c.wantStatus, rr.Body.String())
			continue
		}
		var body apiResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: unmarshal: %v", c.path, err)
			continue
		}
		if body.Status != "ok" {
			t.Errorf("%s: status %q want ok: %s", c.path, body.Status, body.Error)
			continue
		}
		if body.Count != c.wantCount {
			t.Errorf("%s: count %d want %d", c.path, body.Count, c.wantCount)
		}
		if body.Meta.Tool != "riskx" {
			t.Errorf("%s: meta tool %q", c.path, body.Meta.Tool)
		}
	}
}

func TestWriteEndpointsDoNotExist(t *testing.T) {
	// The API is read-only: anything not registered returns 405 for
	// standard verbs when served by http.ServeMux default.
	s, _ := newTestServer(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/v1/findings", nil)
		rr := httptest.NewRecorder()
		s.mux.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Errorf("%s %s must not succeed: read-only API", m, "/api/v1/findings")
		}
	}
}

func TestResolveAPIKeyEnvWinsOverConfig(t *testing.T) {
	t.Setenv("RISKX_API_KEY", "env-key")
	if got := ResolveAPIKey("config-key"); got != "env-key" {
		t.Fatalf("env must win: got %q", got)
	}
	// Env unset: config value is used.
	os.Unsetenv("RISKX_API_KEY")
	if got := ResolveAPIKey("config-key"); got != "config-key" {
		t.Fatalf("config fallback failed: got %q", got)
	}
}
