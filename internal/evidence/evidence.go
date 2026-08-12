// Package evidence implements the mandatory evidence system (spec §19, §44).
//
// Every finding must be able to answer: "Why did you say this is risky?"
// An EvidenceSet collects evidence items, each with a type, source, timestamp,
// value, and an in-project source citation (organization/document/url/accessed/
// version). Citing a source that was not actually consulted is prohibited.
package evidence

import (
	"fmt"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// Source defines a consulted external source with its metadata (spec §44).
// Only sources actually consulted may be registered; URLs must never be
// fabricated.
type Source struct {
	Organization string
	Document     string
	URL          string
	Accessed     string // YYYY-MM-DD
	Version      string
}

// Validate checks that required citation fields are present.
func (s Source) Validate() error {
	if s.Organization == "" || s.Document == "" || s.URL == "" || s.Accessed == "" {
		return fmt.Errorf("evidence source missing required citation fields")
	}
	return nil
}

// Citation returns the in-project citation metadata.
func (s Source) Citation() models.SourceCitation {
	return models.SourceCitation{
		Organization: s.Organization,
		Document:     s.Document,
		URL:          s.URL,
		Accessed:     s.Accessed,
		Version:      s.Version,
	}
}

// Well-known authoritative sources consulted during Phase 0 research.
// These are the sources the code may cite; more may be added as features are
// verified against their primary documentation.
var (
	CISAKEV = Source{
		Organization: "CISA",
		Document:     "Known Exploited Vulnerabilities Catalog",
		URL:          "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
		Accessed:     "2026-08-12",
	}
	NVDAPI = Source{
		Organization: "NIST NVD",
		Document:     "NVD API 2.0",
		URL:          "https://nvd.nist.gov/developers/vulnerabilities",
		Accessed:     "2026-08-12",
	}
	FIRSTEPSS = Source{
		Organization: "FIRST",
		Document:     "Exploit Prediction Scoring System (EPSS)",
		URL:          "https://www.first.org/epss/",
		Accessed:     "2026-08-12",
	}
	OSVAPI = Source{
		Organization: "Google OSV",
		Document:     "OSV.dev API",
		URL:          "https://osv.dev/docs/",
		Accessed:     "2026-08-12",
	}
	OWASPMCP = Source{
		Organization: "OWASP",
		Document:     "OWASP MCP Top 10",
		URL:          "https://owasp.org/www-project-mcp-top-10/",
		Accessed:     "2026-08-12",
		Version:      "v0.1",
	}
	MCPSpec = Source{
		Organization: "Anthropic / MCP",
		Document:     "Model Context Protocol Security Best Practices",
		URL:          "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices",
		Accessed:     "2026-08-12",
	}
	OWASPTop10 = Source{
		Organization: "OWASP",
		Document:     "OWASP Top 10:2025",
		URL:          "https://owasp.org/Top10/2025/0x00_2025-Introduction/",
		Accessed:     "2026-08-12",
	}
	CISControls = Source{
		Organization: "CIS",
		Document:     "CIS Critical Security Controls v8.1",
		URL:          "https://www.cisecurity.org/controls/v8",
		Accessed:     "2026-08-12",
		Version:      "v8.1",
	}
	MITREATTACK = Source{
		Organization: "MITRE",
		Document:     "MITRE ATT&CK (STIX data)",
		URL:          "https://github.com/mitre-attack/attack-stix-data",
		Accessed:     "2026-08-12",
		Version:      "v19.2",
	}
)

// Set accumulates evidence items with optional source citations.
type Set struct {
	items []models.Evidence
}

// NewSet returns an empty evidence set.
func NewSet() *Set { return &Set{} }

// Add appends an evidence item with its citation metadata.
func (s *Set) Add(typ, source, value string, cited Source) {
	s.items = append(s.items, models.Evidence{
		Type:      typ,
		Source:    source,
		Timestamp: time.Now().UTC(),
		Value:     value,
		Citation:  cited.Citation(),
	})
}

// AddRaw appends an evidence item without an external citation (internal
// observations such as network measurements).
func (s *Set) AddRaw(typ, source, value string) {
	s.items = append(s.items, models.Evidence{
		Type:      typ,
		Source:    source,
		Timestamp: time.Now().UTC(),
		Value:     value,
	})
}

// Items returns a copy of the collected evidence.
func (s *Set) Items() []models.Evidence {
	out := make([]models.Evidence, len(s.items))
	copy(out, s.items)
	return out
}

// Has reports whether any evidence of the given type exists.
func (s *Set) Has(typ string) bool {
	for _, e := range s.items {
		if e.Type == typ {
			return true
		}
	}
	return false
}
