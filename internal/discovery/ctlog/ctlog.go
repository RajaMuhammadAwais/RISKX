// Package ctlog implements passive certificate-transparency discovery: it
// reads publicly logged TLS certificates to enumerate the names (domains and
// subdomains) for which certificates have been issued. No network packets
// are sent to the target: this is pure observation of public records.
//
// Primary source (verified live 2026-08-12):
//   - Certspotter v1, SSLMate's public CT aggregator:
//     GET https://api.certspotter.com/v1/issuances?domain=<domain>&expand=dns_names&expand=issuer&expand=revocation
//     returns JSON array {id, cert_sha256, dns_names[], pubkey_sha256,
//     issuer{friendly_name,name}, not_before, not_after, revoked,
//     revocation{time,reason,checked_at}}. No API key required.
//
// Rules (no guessing, spec §15):
//   - Only names verifiably present in logged certificates are reported.
//     Wildcard SANs (e.g. "*.x") are reported AS-IS with a wildcard flag;
//     they are NEVER expanded into guessed concrete hostnames.
//   - Every discovered name is a separate asset with its own provenance:
//     the CT record it came from, the issuer, the validity window, the
//     access date, and the provider attribution.
//   - crt.sh is a documented alternative source
//     (crt.sh/?q=%25.<d>&output=json) but was UNREACHABLE at verification
//     time (2026-08-12, persistent 502); it is only used if explicitly
//     configured as an additional provider via Source list.
//   - Unreachable providers are reported in the visibility metadata, never
//     silently dropped (spec §48).
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// DefaultProvider is the verified public CT endpoint used for discovery.
const DefaultProvider = "certspotter"

const certspotterURL = "https://api.certspotter.com/v1/issuances?domain=%s&expand=dns_names&expand=issuer&expand=revocation"

// certspotterIssuance is the verified response record shape.
type certspotterIssuance struct {
	ID           string    `json:"id"`
	DNSNames     []string  `json:"dns_names"`
	CertSHA256   string    `json:"cert_sha256"`
	PubkeySHA256 string    `json:"pubkey_sha256"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Revoked      bool      `json:"revoked"`
	Issuer       struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
}

// Client is the HTTP contract so tests can inject a fake transport.
type Client interface {
	Do(*http.Request) (*http.Response, error)
}

// Discover enumerates certificate-transparency records for the given apex
// domain. A nil client uses http.DefaultClient.
func Discover(ctx context.Context, client Client, domain string) ([]models.Asset, []models.Evidence, []string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, nil, nil, fmt.Errorf("ctlog: empty domain")
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	url := fmt.Sprintf(certspotterURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ctlog: request build: %w", err)
	}
	req.Header.Set("User-Agent", "riskx-ctlog/0.3.0 (evidence-based CT discovery)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, []string{"provider_unreachable"},
			fmt.Errorf("ctlog: %s request failed: %w", DefaultProvider, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, []string{"provider_error"},
			fmt.Errorf("ctlog: %s returned %d", DefaultProvider, resp.StatusCode)
	}
	var records []certspotterIssuance
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, nil, nil, fmt.Errorf("ctlog: %s response decode: %w", DefaultProvider, err)
	}

	now := time.Now().UTC()
	accessed := now.Format("2006-01-02")
	var assets []models.Asset
	var evidence []models.Evidence
	seen := make(map[string]bool)

	for _, rec := range records {
		for _, name := range rec.DNSNames {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || seen[name] {
				continue
			}
			isTarget := name == domain || strings.HasSuffix(name, "."+domain)
			wildcard := strings.HasPrefix(name, "*.")
			seen[name] = true

			asset := models.Asset{
				ID:    models.ContentID("ctlog", name, rec.CertSHA256),
				Kind:  models.KindDomain,
				Value: name,
				Host:  name,
				Exposure: models.ExposureUnknown,
				FirstSeen: rec.NotBefore,
				LastSeen:  now,
				Provenance: models.Provenance{
					Source:     "certificate_transparency",
					Method:     "ctlog_enumeration",
					Timestamp:  now,
					Confidence: models.ConfidenceHigh,
					},
				Fingerprint: models.Fingerprint{
					TLSSANs:   []string{name},
					TLSIssuer: rec.Issuer.FriendlyName,
					Banner: fmt.Sprintf("wildcard=%t co_hosted=%t cert=%s revoked=%t not_after=%s",
						wildcard, !isTarget, rec.CertSHA256, rec.Revoked,
						rec.NotAfter.UTC().Format(time.RFC3339)),
				},
				Schema: models.SchemaAsset,
			}
			assets = append(assets, asset)

			ev := models.Evidence{
				Type: "certificate", Source: "certificate_transparency", Timestamp: now,
				Value: fmt.Sprintf("name=%s cert=%s issuer=%q not_before=%s not_after=%s wildcard=%t",
					name, rec.CertSHA256, rec.Issuer.FriendlyName,
					rec.NotBefore.UTC().Format(time.RFC3339), rec.NotAfter.UTC().Format(time.RFC3339), wildcard),
				Citation: models.SourceCitation{
					Organization: "SSLMate",
					Document:     "Certspotter CT Search API",
					URL:          url,
					Accessed:     accessed,
					Version:      "v1",
				},
			}
			if rec.Revoked {
				ev.Value += " revoked=true"
			}
			evidence = append(evidence, ev)
		}
	}
	return assets, evidence, nil, nil
}
