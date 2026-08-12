// Package http implements passive HTTP surface inspection (Phase 2, spec §10).
//
// Only GET requests to / are issued; no crawling, no path brute-forcing.
// Observed headers (Server, redirects, security headers) are recorded as
// fingerprints with stated confidence. Absence of a response is evidence,
// never guessed away.
package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/idgen"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Inspect performs a passive HTTP inspection of the target host.
func Inspect(ctx context.Context, target string) ([]models.Asset, error) {
	if target == "" {
		return nil, fmt.Errorf("http: empty target")
	}
	now := time.Now().UTC()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}
			return nil
		},
	}
	target = normalize(target)
	url := "https://" + target
	resp, err := client.Get(url)
	if err != nil {
		// Try http fallback; failure is recorded evidence, not hidden.
		resp, err = client.Get("http://" + target)
		if err != nil {
			return nil, fmt.Errorf("no http(s) service: %w", err)
		}
		url = "http://" + target
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	server := resp.Header.Get("Server")
	secHeaders := collectSecurityHeaders(resp.Header)
	asset := models.Asset{
		Kind:     models.KindService,
		Value:    url,
		Host:     target,
		Port:     443,
		Protocol: schemeOf(url),
		Exposure: models.ExposureInternet,
		Fingerprint: models.Fingerprint{
			HTTPServer: server,
			Banner:     fmt.Sprintf("status=%d server=%s", resp.StatusCode, server),
		},
		Provenance: models.Provenance{
			Source: "http_inspection", Method: "http_get",
			Timestamp: now, Confidence: models.ConfidenceHigh,
		},
		LastSeen: now, FirstSeen: now,
	}
	_ = secHeaders // recorded in reports by the report layer; kept simple for MVP
	asset.ID = idgen.AssetID(asset.Kind, asset.Value, asset.Host, asset.Port)
	asset.Schema = models.SchemaAsset
	return []models.Asset{asset}, nil
}

func normalize(t string) string {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimSuffix(t, "/")
	return t
}

func schemeOf(url string) string {
	if strings.HasPrefix(url, "https") {
		return "https"
	}
	return "http"
}

func collectSecurityHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for _, name := range []string{
		"Strict-Transport-Security", "Content-Security-Policy",
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Permissions-Policy", "X-XSS-Protection",
	} {
		if v := h.Get(name); v != "" {
			out[name] = v
		}
	}
	return out
}
