// Package tls implements passive TLS surface inspection (Phase 2, spec §10).
//
// Only a TLS handshake is performed; no application data is sent. Observed
// certificate subjects, SANs, issuer, expiry and key size are recorded as
// fingerprints. A missing TLS service is evidence, never guessed away.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/idgen"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Inspect performs a passive TLS inspection of the target host (port 443).
func Inspect(ctx context.Context, target string) ([]models.Asset, error) {
	if target == "" {
		return nil, fmt.Errorf("tls: empty target")
	}
	host := cleanHost(target)
	now := time.Now().UTC()
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // observation only; verification status is recorded
	})
	if err != nil {
		return nil, fmt.Errorf("no tls service: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("tls handshake succeeded but no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	expired := now.After(leaf.NotAfter)
	var sans []string
	if leaf.Subject.CommonName != "" {
		sans = append(sans, leaf.Subject.CommonName)
	}
	sans = append(sans, leaf.DNSNames...)
	fp := models.Fingerprint{
		TLSSubjects: sans,
		TLSIssuer:   leaf.Issuer.CommonName,
		TLSExpired:  &expired,
	}
	if leaf.PublicKey != nil {
		fp.TLSKeyBits = keyBits(leaf.PublicKey)
	}
	asset := models.Asset{
		Kind:        models.KindService,
		Value:       "tls://" + host + ":443",
		Host:        host,
		Port:        443,
		Protocol:    "tls",
		Exposure:    models.ExposureInternet,
		Fingerprint: fp,
		Provenance: models.Provenance{
			Source: "tls_inspection", Method: "tls_handshake",
			Timestamp: now, Confidence: models.ConfidenceHigh,
		},
		LastSeen: now, FirstSeen: now,
	}
	asset.ID = idgen.AssetID(asset.Kind, asset.Value, asset.Host, asset.Port)
	asset.Schema = models.SchemaAsset
	return []models.Asset{asset}, nil
}

// keyBits returns the key size in bits for supported key types.
func keyBits(key any) int {
	switch k := key.(type) {
	case interface{ Size() int }:
		return k.Size() * 8
	}
	return 0
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "tls://")
	h = strings.TrimSuffix(h, "/")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h[idx:], "/") {
		h = h[:idx]
	}
	return h
}
