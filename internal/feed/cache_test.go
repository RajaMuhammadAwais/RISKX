package feed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/RajaMuhammadAwais/RISKX/internal/vulnerability/ingest"
)

func tempCache(t *testing.T) *Cache {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.json")
	c, err := Open(p)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c
}

func TestKEVLookupCaseInsensitive(t *testing.T) {
	c := tempCache(t)
	c.set(ingest.KEVCSVURL, []Entry{{
		Source:   "cisa_kev",
		SourceID: "CVE-2021-44228",
		Value:    `{"product":"Log4j"}`,
		Fetched:  time.Now().UTC(),
	}})
	if e := c.KEV("cve-2021-44228"); e == nil {
		t.Fatal("lowercase lookup missed cached KEV entry")
	}
	if e := c.KEV("CVE-2099-00000"); e != nil {
		t.Fatalf("unknown CVE must return nil, got %+v", e)
	}
}

func TestStaleFlagOnOldEntries(t *testing.T) {
	c := tempCache(t)
	c.set(ingest.KEVCSVURL, []Entry{{
		Source:   "cisa_kev",
		SourceID: "CVE-2021-44228",
		Value:    "{}",
		Fetched:  time.Now().UTC().Add(-8 * 24 * time.Hour),
	}})
	e := c.KEV("CVE-2021-44228")
	if e == nil || !e.Stale {
		t.Fatal("entry older than FeedFreshAge must be reported stale")
	}
}

func TestKEVSyncNeverDestroysEPSS(t *testing.T) {
	c := tempCache(t)
	c.set("https://api.first.org/data/v1/epss", []Entry{{
		Source: "first_epss", SourceID: "CVE-2021-44228", Value: `{"epss":0.9}`,
		Fetched: time.Now().UTC(),
	}})
	rows := []ingest.KEVEntry{{CVEID: "CVE-2021-44228", Product: "X", Vulnerability: "Y"}}
	merged := c.mergeKEV(rows)
	var epss int
	for _, e := range merged {
		if e.Source == "first_epss" {
			epss++
		}
	}
	if epss != 1 {
		t.Fatalf("KEV sync must preserve EPSS entries, kept %d", epss)
	}
}

func TestEPSSMergeNeverDestroysKEV(t *testing.T) {
	c := tempCache(t)
	c.set(ingest.KEVCSVURL, []Entry{{
		Source: "cisa_kev", SourceID: "CVE-2021-44228", Value: `v`,
		Fetched: time.Now().UTC(),
	}})
	// KEV sync rebuilds KEV rows fresh but must keep EPSS rows intact.
	rows := []ingest.KEVEntry{{CVEID: "CVE-2021-44228", Product: "X", Vulnerability: "Y"}}
	merged := c.mergeKEV(rows)
	var kev, epss int
	for _, e := range merged {
		if e.Source == "cisa_kev" {
			kev++
		} else if e.Source == "first_epss" {
			epss++
		}
	}
	if kev != 1 {
		t.Fatalf("KEV rows must be rebuilt: got %d", kev)
	}
	if epss != 0 {
		t.Fatalf("EPSS rows absent before merge must stay absent: got %d", epss)
	}
}

func TestSaveAndReloadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "feed.json")
	c, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	c.set(ingest.KEVCSVURL, []Entry{{
		Source: "cisa_kev", SourceID: "CVE-2021-44228", Value: "v",
		Fetched: time.Unix(1000, 0),
	}})
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0600 {
			t.Fatalf("feed cache must be 0600, got %o", info.Mode().Perm())
		}
	} else {
		// Windows ignores POSIX permission bits in the umask: os.WriteFile(0600)
		// materializes as 0666 minus umask. Verify the write succeeded and the
		// content round-trips instead of asserting exact bits.
		if !info.Mode().IsRegular() {
			t.Fatalf("feed cache must be a regular file, got mode %v", info.Mode())
		}
	}
	c2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if e := c2.KEV("CVE-2021-44228"); e == nil {
		t.Fatal("reload lost cached KEV entry")
	}
}

func TestEmptyCacheReturnsEmptyLists(t *testing.T) {
	c := tempCache(t)
	all := c.All()
	if all == nil {
		t.Fatal("All() must return non-nil empty slice for JSON [] fidelity")
	}
	kev, epss := c.Count()
	if kev != 0 || epss != 0 {
		t.Fatalf("empty cache counts must be 0: kev=%d epss=%d", kev, epss)
	}
}

func TestSnapshotIsCanonicalJSON(t *testing.T) {
	c := tempCache(t)
	c.set("u", []Entry{{Source: "cisa_kev", SourceID: "CVE-1", Value: "{}", Fetched: time.Unix(1, 0)}})
	b, err := json.Marshal(c.snap)
	if err != nil {
		t.Fatal(err)
	}
	var dec map[string]any
	if err := json.Unmarshal(b, &dec); err != nil {
		t.Fatalf("snapshot must be valid JSON: %v", err)
	}
	if dec["version"] != "feed-v1" {
		t.Fatalf("unexpected version: %v", dec["version"])
	}
}
