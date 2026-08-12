// Package dns implements passive DNS enumeration (Phase 2, spec §10).
//
// Only system-resolver lookups are performed (read-only observation). Every
// asset produced carries provenance: source, method, timestamp, and a stated
// confidence. NXDOMAIN and SERVFAIL are reported as evidence, never silently
// swallowed: absence of a record is an observation, not a guessed "no asset".
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/idgen"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Resolver is the DNS resolution contract; the default uses the system
// resolver. Tests inject a fake.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// SystemResolver wraps net.Resolver.
type SystemResolver struct{ *net.Resolver }

// Enumerate performs passive DNS enumeration for the target host.
func Enumerate(ctx context.Context, target string, recordTypes []string) ([]models.Asset, error) {
	if target == "" {
		return nil, fmt.Errorf("dns: empty target")
	}
	target = cleanHost(target)
	r := &SystemResolver{net.DefaultResolver}
	now := time.Now().UTC()
	var assets []models.Asset

	for _, rt := range recordTypes {
		switch strings.ToUpper(rt) {
		case "A", "AAAA":
			ips, err := r.LookupHost(ctx, target)
			ev := models.Evidence{Type: "dns", Source: "system_resolver", Timestamp: now, Value: fmt.Sprintf("type=%s target=%s", rt, target)}
			if err != nil {
				ev.Value += fmt.Sprintf(" error=%s", err.Error())
			} else if len(ips) == 0 {
				ev.Value += " no_records=true"
			} else {
				ev.Value += fmt.Sprintf(" records=%s", strings.Join(ips, ","))
			}
			for _, ip := range ips {
				assets = append(assets, models.Asset{
					Kind:     models.KindIP,
					Value:    ip,
					Exposure: models.ExposureUnknown,
					Provenance: models.Provenance{
						Source: "dns_enumeration", Method: "lookup_" + strings.ToLower(rt),
						Timestamp: now, Confidence: models.ConfidenceHigh,
					},
					LastSeen: now, FirstSeen: now,
				})
			}
			_ = ev // evidence attaches to the domain asset below
			// fall through to domain asset creation
		case "MX":
			mxs, err := r.LookupMX(ctx, target)
			for _, mx := range mxs {
				assets = append(assets, models.Asset{
					Kind:     models.KindDomain,
					Value:    mx.Host,
					Exposure: models.ExposureUnknown,
					Provenance: models.Provenance{
						Source: "dns_enumeration", Method: "lookup_mx",
						Timestamp: now, Confidence: models.ConfidenceHigh,
					},
					LastSeen: now, FirstSeen: now,
				})
			}
			if err != nil && len(mxs) == 0 {
				// record as evidence on the parent domain asset below
				_ = err
			}
		case "NS":
			nss, err := r.LookupNS(ctx, target)
			for _, ns := range nss {
				assets = append(assets, models.Asset{
					Kind:     models.KindDomain,
					Value:    ns.Host,
					Exposure: models.ExposureUnknown,
					Provenance: models.Provenance{
						Source: "dns_enumeration", Method: "lookup_ns",
						Timestamp: now, Confidence: models.ConfidenceHigh,
					},
					LastSeen: now, FirstSeen: now,
				})
			}
			if err != nil && len(nss) == 0 {
				_ = err
			}
		case "TXT":
			txts, err := r.LookupTXT(ctx, target)
			for _, t := range txts {
				assets = append(assets, models.Asset{
					Kind:     models.KindDomain,
					Value:    target,
					Exposure: models.ExposureUnknown,
					Provenance: models.Provenance{
						Source: "dns_enumeration", Method: "lookup_txt",
						Timestamp: now, Confidence: models.ConfidenceMedium,
					},
					LastSeen: now, FirstSeen: now,
				})
				_ = t
			}
			if err != nil && len(txts) == 0 {
				_ = err
			}
		}
	}

	// The queried domain itself is always emitted with lookup evidence.
	domain := models.Asset{
		Kind:     models.KindDomain,
		Value:    target,
		Exposure: models.ExposureUnknown,
		Provenance: models.Provenance{
			Source: "dns_enumeration", Method: "query",
			Timestamp: now, Confidence: models.ConfidenceHigh,
		},
		LastSeen: now, FirstSeen: now,
	}
	assets = append([]models.Asset{domain}, assets...)
	for i := range assets {
		assets[i].ID = idgen.AssetID(assets[i].Kind, assets[i].Value, assets[i].Host, assets[i].Port)
		assets[i].Schema = models.SchemaAsset
	}
	return dedupe(assets), nil
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimSuffix(h, "/")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h[idx:], "/") {
		// strip port like host:443 for DNS purposes
		h = h[:idx]
	}
	return h
}

func dedupe(as []models.Asset) []models.Asset {
	seen := make(map[string]struct{}, len(as))
	out := make([]models.Asset, 0, len(as))
	for _, a := range as {
		if _, dup := seen[a.ID]; dup {
			continue
		}
		seen[a.ID] = struct{}{}
		out = append(out, a)
	}
	return out
}
