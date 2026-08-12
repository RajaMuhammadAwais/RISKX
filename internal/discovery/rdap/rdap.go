// Package rdap implements passive RDAP lookups for domain registration evidence
// (Phase 2.4). Classic WHOIS is deferred; RDAP at data.rdap.org is the only
// used source, and every registration fact carries the RDAP citation.
//
// Absence of RDAP data is recorded as incomplete visibility, never guessed
// into a "not registered" conclusion (spec §48).
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/evidence"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

const rdapURL = "https://data.rdap.org/domain/"

// Lookup fetches registration evidence for the target domain.
func Lookup(ctx context.Context, domain string) (models.Provenance, models.Fingerprint, error) {
	if domain == "" {
		return models.Provenance{}, models.Fingerprint{}, fmt.Errorf("rdap: empty domain")
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapURL+domain, nil)
	if err != nil {
		return models.Provenance{}, models.Fingerprint{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return models.Provenance{}, models.Fingerprint{}, fmt.Errorf("rdap unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return models.Provenance{}, models.Fingerprint{}, fmt.Errorf("rdap: %s not found (visibility incomplete, not absence)", domain)
	}
	if resp.StatusCode >= 400 {
		return models.Provenance{}, models.Fingerprint{}, fmt.Errorf("rdap: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return models.Provenance{}, models.Fingerprint{}, err
	}
	var doc rdapDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return models.Provenance{}, models.Fingerprint{}, fmt.Errorf("rdap: invalid payload: %w", err)
	}
	now := time.Now().UTC()
	fp := models.Fingerprint{
		Registrar:     registrarOf(doc),
		RegisteredOrg: orgOf(doc),
	}
	prov := models.Provenance{
		Source: "rdap", Method: "rdap_lookup", Timestamp: now,
		Confidence: models.ConfidenceHigh,
	}
	return prov, fp, nil
}

// CitedSource returns the RDAP source citation for findings.
func CitedSource() evidence.Source {
	return evidence.Source{
		Organization: "ARIN (RDAP bootstrap)",
		Document:     "RDAP domain lookup (data.rdap.org)",
		URL:          rdapURL,
		Accessed:     "2026-08-12",
	}
}

type rdapDoc struct {
	LD        string   `json:"ldContextName,omitempty"`
	ClassName string   `json:"objectClassName"`
	Events    []event  `json:"events,omitempty"`
	Entities  []entity `json:"entities,omitempty"`
}

type event struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type entity struct {
	Roles  []string      `json:"roles,omitempty"`
	VCard  []interface{} `json:"vcardArray,omitempty"`
}

func registrarOf(doc rdapDoc) string {
	for _, e := range doc.Entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, "registrar") {
				return orgNameOf(e)
			}
		}
	}
	return ""
}

func orgOf(doc rdapDoc) string {
	for _, e := range doc.Entities {
		if len(e.Roles) > 0 && strings.EqualFold(e.Roles[0], "registrant") {
			return orgNameOf(e)
		}
	}
	return ""
}

// orgNameOf extracts the organization name from the first vCard ORG entry.
func orgNameOf(e entity) string {
	if len(e.VCard) < 2 {
		return ""
	}
	entries, ok := e.VCard[1].([]interface{})
	if !ok {
		return ""
	}
	for _, ent := range entries {
		arr, ok := ent.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		if s, ok := arr[0].(string); !ok || !strings.EqualFold(s, "org") {
			continue
		}
		vals, ok := arr[3].([]interface{})
		if !ok || len(vals) == 0 {
			continue
		}
		if s, ok := vals[0].(string); ok {
			return s
		}
	}
	return ""
}


