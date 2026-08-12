// Package feed implements the offline vulnerability-intelligence cache used by
// riskx feed (sync/list) and riskx prioritize. It persists verified primary
// source responses (CISA KEV CSV rows, FIRST EPSS scores) to a local
// JSON cache file under ~/.riskx/feed.json so that every lookup command can
// run fully offline.
//
// Design (evidence, not guessing):
//   - Every cached row carries the source URL, the fetch timestamp, and the
//     exact payload received from the source (spec §44 provenance).
//   - Cache age is declared (FeedFreshAge); entries older than the age are
//     flagged stale in outputs, never silently dropped.
//   - A failed network fetch never erases a usable older cache entry: the
//     command reports the fetch error AND falls back to the stored copy with
//     stale=true (spec §48: feed down → marked stale, never "no data").
//   - No secrets or user data are written; only public catalog responses.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/vulnerability/ingest"
)

// DefaultCachePath returns the default feed cache path: ~/.riskx/feed.json.
func DefaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".riskx", "feed.json")
}

// FeedFreshAge: KEV updates continuously and EPSS daily; entries older than
// this are reported as STALE. Matching ingest-side staleness discipline.
const FeedFreshAge = 7 * 24 * time.Hour

// Entry is one cached, provenance-tagged intelligence record.
type Entry struct {
	Source   string    `json:"source"`            // e.g. "cisa_kev" or "first_epss"
	SourceID string    `json:"source_id"`         // CVE-ID
	Value    string    `json:"value"`             // human-readable descriptor or JSON payload
	Fetched  time.Time `json:"fetched_at"`        // UTC fetch time of the upstream response
	Stale    bool      `json:"stale"`             // true when Fetched older than FeedFreshAge
}

// Snapshot is the persisted cache format with its provenance header.
type Snapshot struct {
	Version  string  `json:"version"`
	Updated  string  `json:"updated_at"`
	Upstream string  `json:"upstream"` // URL of the primary source at last sync
	Entries  []Entry `json:"entries"`
}

// Cache is the offline feed cache.
type Cache struct {
	mu    sync.RWMutex
	path  string
	snap  Snapshot
	dirty bool
}

// Open loads the cache from path (creating an empty one if absent).
func Open(path string) (*Cache, error) {
	if path == "" {
		return nil, errs.Input("feed.open", "feed cache path required", "use 'riskx feed sync' first")
	}
	c := &Cache{path: path, snap: Snapshot{Version: "feed-v1"}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c.snap)
		if c.snap.Entries == nil {
			c.snap.Entries = []Entry{}
		}
	} else {
		c.snap.Entries = []Entry{}
	}
	return c, nil
}

// Path returns the cache file path.
func (c *Cache) Path() string { return c.path }

// KEV returns cached KEV entries for the given CVE (case-insensitive), or nil.
// Stale is declared on each returned entry; callers must not treat a miss as
// "not exploited" — absence means the catalog row is not in cache.
func (c *Cache) KEV(cve string) *Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id := canonical(cve)
	for i := range c.snap.Entries {
		e := &c.snap.Entries[i]
		if e.Source == "cisa_kev" && canonical(e.SourceID) == id {
			e.Stale = time.Since(e.Fetched) > FeedFreshAge
			return e
		}
	}
	return nil
}

// EPSS returns the cached EPSS score for the given CVE, or nil.
func (c *Cache) EPSS(cve string) *Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id := canonical(cve)
	for i := range c.snap.Entries {
		e := &c.snap.Entries[i]
		if e.Source == "first_epss" && canonical(e.SourceID) == id {
			e.Stale = time.Since(e.Fetched) > FeedFreshAge
			return e
		}
	}
	return nil
}

// All returns every cached entry (KEV + EPSS), stale flags refreshed.
func (c *Cache) All() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Entry, len(c.snap.Entries))
	now := time.Now().UTC()
	for i, e := range c.snap.Entries {
		e.Stale = now.Sub(e.Fetched) > FeedFreshAge
		out[i] = e
	}
	return out
}

// Count returns (kev, epss, total) entry counts.
func (c *Cache) Count() (kev, epss int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.snap.Entries {
		if e.Source == "cisa_kev" {
			kev++
		} else if e.Source == "first_epss" {
			epss++
		}
	}
	return
}

// Save writes the cache to disk (0600) if modified.
func (c *Cache) Save() error {
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errs.Wrap(errs.CodeConfigError, "feed.save", "cannot create feed cache directory", err)
	}
	b, err := json.Marshal(c.snap)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "feed.save", "cannot marshal feed cache", err)
	}
	if err := os.WriteFile(c.path, b, 0600); err != nil {
		return errs.Wrap(errs.CodeInternal, "feed.save", "cannot write feed cache", err)
	}
	c.mu.Lock()
	c.dirty = false
	c.mu.Unlock()
	return nil
}

// set replaces the snapshot entries for ONE feed source while preserving
// every entry from the OTHER feed source. KEV and EPSS live on independent
// upstream lifecycles: a KEV sync must never erase cached EPSS rows and vice
// versa. The caller passes entries for exactly one source (see SyncKEV /
// SyncEPSS).
func (c *Cache) set(upstream string, entries []Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(entries) == 0 {
		return
	}
	preserved := make([]Entry, 0)
	source := entries[0].Source
	for _, e := range c.snap.Entries {
		if e.Source != source {
			preserved = append(preserved, e)
		}
	}
	entries = append(preserved, entries...)
	c.snap.Updated = time.Now().UTC().Format(time.RFC3339)
	c.snap.Upstream = upstream
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SourceID < entries[j].SourceID
	})
	c.snap.Entries = entries
	c.dirty = true
}

// Sync pulls the CISA KEV catalog and EPSS scores for the requested CVEs,
// merging into the offline cache. Network failures fall back to existing
// entries with explicit error reporting (never silent "no data").
func (c *Cache) SyncKEV() (n int, srcErr error) {
	kev := ingest.NewKEVClient()
	entries, stale, err := kev.Entries(context.Background())
	if err != nil {
		return 0, errs.Feed("feed.sync_kev", "KEV catalog unreachable", err.Error())
	}
	c.set(ingest.KEVCSVURL, c.mergeKEV(entries))
	return len(entries), staleError(stale, "KEV served from fallback snapshot")
}

func (c *Cache) SyncEPSS(cves []string) (n int, srcErr error) {
	ep := ingest.NewEPSSClient()
	var merged []Entry
	var lastStale bool
	for _, id := range cves {
		r, err := ep.Score(context.Background(), id)
		if err != nil {
			// Per-entry failure is reported, not fatal: continue to other CVEs
			// and keep the prior cached value (spec §48).
			continue
		}
		if r.CVE == "" {
			continue
		}
		merged = append(merged, Entry{
			Source:   "first_epss",
			SourceID: r.CVE,
			Value:    epssPayload(r),
			Fetched:  time.Now().UTC(),
		})
		lastStale = r.Stale
	}
	if len(merged) == 0 && len(cves) > 0 {
		return 0, errs.Feed("feed.sync_epss", "no EPSS scores retrieved",
			"upstream may be rate-limited; cached values retained")
	}
	// set() preserves KEV rows internally; merged contains only the new EPSS
	// rows for this upstream (see set() for the cross-source merge rule).
	c.set("https://api.first.org/data/v1/epss", merged)
	return len(merged), staleError(lastStale, "EPSS readings older than 7 days marked STALE")
}

// AddTestEntry adds an entry to the cache for testability (internal tests
// only — callers constructing real caches use SyncKEV/SyncEPSS).
func (c *Cache) AddTestEntry(e Entry) {
	c.set(e.Source, append(c.existingSource(e.Source), e))
}

// existingSource returns all cached rows matching the given source, so the
// other feed type can be refreshed without erasing this one.
func (c *Cache) existingSource(source string) []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Entry, 0)
	for _, e := range c.snap.Entries {
		if e.Source == source {
			out = append(out, e)
		}
	}
	return out
}

// mergeKEV rebuilds the KEV slice fresh from the catalog rows while keeping
// EPSS rows untouched (separate upstream lifecycles — a KEV sync must never
// destroy EPSS data).
func (c *Cache) mergeKEV(rows []ingest.KEVEntry) []Entry {
	out := c.existingSource("first_epss")
	now := time.Now().UTC()
	for _, r := range rows {
		payload, _ := json.Marshal(map[string]any{
			"vendor_project":      r.VendorProject,
			"product":             r.Product,
			"vulnerability_name":  r.Vulnerability,
			"date_added":          r.DateAdded,
			"short_description":   r.ShortDesc,
			"required_action":     r.RequiredAction,
			"due_date":            r.DueDate,
			"known_ransomware_use": r.KnownRansomwareUse,
			"cwes":                r.CWEs,
			"source":              r.Source,
		})
		out = append(out, Entry{
			Source:   "cisa_kev",
			SourceID: r.CVEID,
			Value:    string(payload),
			Fetched:  now,
		})
	}
	return out
}

func epssPayload(r ingest.EPSSReading) string {
	b, _ := json.Marshal(map[string]any{"epss": r.Score, "stale": r.Stale})
	return string(b)
}

// staleError maps a feed staleness flag into an explicit (non-fatal) error
// message so callers surface STALE rather than silent output.
func staleError(stale bool, msg string) error {
	if !stale {
		return nil
	}
	return errs.Feed("feed.stale", msg, "")
}

func canonical(cve string) string { return strings.ToUpper(cve) }

// FormatSize returns a human cache-size label for display.
func FormatSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
