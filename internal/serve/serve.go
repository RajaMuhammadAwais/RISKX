// Package serve implements the RISKX read-only evidence API server
// (roadmap P0: serve mode). It exposes the storage-v1 evidence store over a
// local HTTP API so that dashboards, CI systems, and AI agents can consume
// RISKX's canonical, evidence-provenanced data without re-running scans.
//
// Rules (research-backed, no guessing):
//   - The server is strictly READ-ONLY: it exposes assets, findings, risk
//     scores, evidence, and relationships; nothing can be written through
//     the API. Storage-v1 remains the single write path.
//   - Authentication is user-supplied: an API key set via the
//     RISKX_API_KEY environment variable (or config serve.api_key), never
//     embedded in the binary. Without a configured key the server refuses
//     to start rather than run unauthenticated (fail secure).
//   - Keys are compared with crypto/subtle.ConstantTimeCompare to avoid
//     timing side channels.
//   - Every response is canonical JSON with scan metadata, consistent with
//     the --json output contract (spec §44).
package serve

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/log"
	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// ServerConfig holds serve-mode configuration. Key must be non-empty; the
// caller (cmd layer) merges config file + environment with precedence:
// RISKX_API_KEY env overrides config file value.
type ServerConfig struct {
	// Listen is "host:port". Default ":8090".
	Listen string
	// Key is the user-supplied API key (env RISKX_API_KEY preferred).
	Key string
	// StorePath is the evidence store path (--data / RISKX_DATA).
	StorePath string
	// ReadTimeout bounds per-request processing.
	ReadTimeout time.Duration
	// Now is the clock source; tests may substitute.
	Now func() time.Time
}

// DefaultServerConfig returns secure defaults. The default listen address
// binds all interfaces on a local port; operators SHOULD override with
// 127.0.0.1:port for local-only exposure. The server never starts without a
// configured API key.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Listen:      ":8090",
		ReadTimeout: 10 * time.Second,
		Now:         time.Now,
	}
}

// Server is the RISKX evidence API server.
type Server struct {
	cfg   ServerConfig
	store *storage.Store
	mux   *http.ServeMux
}

// apiResponse wraps every response with scan metadata for provenance.
type apiResponse struct {
	Status    string              `json:"status"` // ok|error
	Error     string              `json:"error,omitempty"`
	API       string              `json:"api_version"`
	Count     int                 `json:"count,omitempty"`
	Data      any                 `json:"data,omitempty"`
	Meta      models.ScanMetadata `json:"meta"`
	Generated string              `json:"generated_at"`
}

func (s *Server) newResponse(status string, count int, data any, err error) apiResponse {
	now := s.cfg.Now
	if now == nil {
		now = time.Now
	}
	r := apiResponse{
		Status:    status,
		API:       "api-v1",
		Count:     count,
		Data:      data,
		Meta:      scanMeta(),
		Generated: now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		r.Status = "error"
		r.Error = err.Error()
		r.Count = 0
		r.Data = nil
	}
	return r
}

func scanMeta() models.ScanMetadata {
	return models.ScanMetadata{
		Tool:           "riskx",
		ToolVersion:    config.ToolVersion,
		RiskModel:      "risk-v1",
		AssetSchema:    "asset-v1",
		FindingSchema:  "finding-v1",
		EvidenceSchema: "evidence-v1",
		Mode:           "serve",
		StartedAt:      time.Now().UTC(),
		FinishedAt:     time.Now().UTC(),
	}
}

// New validates the configuration and opens the evidence store. An empty key
// is a configuration error: the server refuses to run unauthenticated.
func New(cfg ServerConfig) (*Server, error) {
	if strings.TrimSpace(cfg.Key) == "" {
		return nil, errs.New(errs.CodeConfigError, "serve.key",
			"no API key configured; set RISKX_API_KEY or serve.api_key in config")
	}
	if cfg.Listen == "" {
		return nil, errs.New(errs.CodeConfigError, "serve.listen", "listen address is empty")
	}
	if cfg.StorePath == "" {
		return nil, errs.New(errs.CodeConfigError, "serve.data",
			"no evidence store configured; set --data or RISKX_DATA")
	}
	store, err := storage.Open(cfg.StorePath)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.auth(s.handleHealth))
	s.mux.HandleFunc("GET /api/v1/assets", s.auth(s.handleAssets))
	s.mux.HandleFunc("GET /api/v1/findings", s.auth(s.handleFindings))
	s.mux.HandleFunc("GET /api/v1/scores", s.auth(s.handleScores))
	s.mux.HandleFunc("GET /api/v1/evidence", s.auth(s.handleEvidence))
	s.mux.HandleFunc("GET /api/v1/relationships", s.auth(s.handleRelationships))
	s.mux.HandleFunc("GET /api/v1/summary", s.auth(s.handleSummary))
}

// auth wraps a handler with X-API-Key authentication. Requests without a
// header, or with a mismatching key, receive 401 and are logged.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("X-API-Key")) == 0 {
			log.Warn("serve: unauthorized request without API key", "remote", r.RemoteAddr)
			s.writeJSON(w, http.StatusUnauthorized, s.newResponse("error", 0, nil,
				errs.New(errs.CodeAuthRequired, "serve.auth", "missing X-API-Key header")))
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(s.cfg.Key)) != 1 {
			log.Warn("serve: unauthorized request with invalid API key", "remote", r.RemoteAddr)
			s.writeJSON(w, http.StatusUnauthorized, s.newResponse("error", 0, nil,
				errs.New(errs.CodeAuthRequired, "serve.auth", "invalid X-API-Key header")))
			return
		}
		next(w, r)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"server": "riskx-serve",
		"api":    "api-v1",
		"store":  s.cfg.StorePath,
	})
}

func (s *Server) handleAssets(w http.ResponseWriter, _ *http.Request) {
	assets, err := s.store.ListAssets()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", len(assets), assets, nil))
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListFindings()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		filtered := make([]models.Finding, 0, len(findings))
		for _, f := range findings {
			if strings.EqualFold(string(f.Severity), sev) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", len(findings), findings, nil))
}

func (s *Server) handleScores(w http.ResponseWriter, _ *http.Request) {
	scores, err := s.store.ListRiskScores()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", len(scores), scores, nil))
}

// handleEvidence returns evidence rows, optionally filtered by ?finding=<id>
// or ?asset=<id>. Rows are returned as stored JSON payloads with their
// linked IDs so consumers can reconstruct provenance.
func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := r.URL.Query().Get("finding")
	assetID := r.URL.Query().Get("asset")
	rows, err := s.store.ListEvidenceFiltered(findingID, assetID)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", len(rows), rows, nil))
}

func (s *Server) handleRelationships(w http.ResponseWriter, _ *http.Request) {
	rels, err := s.store.ListRelationships()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", len(rels), rels, nil))
}

// handleSummary returns counts plus an asset-kinds breakdown — the
// "dashboard headline" response, derived purely from stored rows.
func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	assets, findings, rels, err := s.store.Count()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, s.newResponse("error", 0, nil, err))
		return
	}
	s.writeJSON(w, http.StatusOK, s.newResponse("ok", 0, map[string]any{
		"assets":        assets,
		"findings":      findings,
		"relationships": rels,
	}, nil))
}

// Serve starts the server and blocks until the context is cancelled. The
// returned error is nil only on clean shutdown; listener failures are
// returned immediately so the CLI can report them.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "serve.listen", "listener failed", err)
	}
	srv := &http.Server{
		Handler:     s.mux,
		ReadTimeout: s.cfg.ReadTimeout,
	}
	errCh := make(chan error, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		if e := srv.Serve(ln); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
		close(errCh)
	}()
	log.Info("serve: evidence API listening", "listen", s.cfg.Listen, "auth", "X-API-Key required")
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case e := <-errCh:
		return e
	}
}

// Close releases the evidence store.
func (s *Server) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

// ResolveAPIKey merges config file and environment. Environment wins:
// secrets on the command line or in process args are avoided; the env var is
// the recommended path (user adds it themselves, never committed).
func ResolveAPIKey(configKey string) string {
	if k := strings.TrimSpace(os.Getenv("RISKX_API_KEY")); k != "" {
		return k
	}
	return strings.TrimSpace(configKey)
}
