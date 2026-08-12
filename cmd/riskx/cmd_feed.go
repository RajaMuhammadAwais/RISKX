package main

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/feed"
)

// --- feed -----------------------------------------------------------------

// newFeedCmd returns the "feed" command family (feed-v1).
//
// Design (evidence, not guessing):
//   - feed sync pulls verified primary sources (CISA KEV, FIRST EPSS) and
//     persists provenance-tagged responses to ~/.riskx/feed.json.
//   - feed list prints the local cache — no network call. Offline-first:
//     downstream commands (riskx prioritize) never need live access to the
//     upstream catalogs.
//   - Stale entries are declared STALE in output; a network failure never
//     erases a usable cache (spec §48: feed down → marked stale, never
//     "no data").
func newFeedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feed <subcommand>",
		Short: "Manage the offline intelligence cache (KEV / EPSS)",
		Long: `feed maintains a local, provenance-tagged cache of verified primary
sources: the CISA Known Exploited Vulnerabilities (KEV) catalog and FIRST EPSS
exploit-probability scores. Commands that enrich findings (e.g. riskx
prioritize) read from this cache, so they never need live upstream access and
never emit findings built on unverified, live-only data.

Cache discipline (no-guessing rule):
  - every row records the source URL and fetch time;
  - entries older than 7 days are reported as STALE, never silently trusted;
  - a failed fetch keeps the last usable cache and reports the failure
    explicitly (spec §48: feed down → marked stale, never "no data").`,
		Example: "  riskx feed sync                      # pull KEV catalog into ~/.riskx/feed.json\n  riskx feed list --stale          # list cached entries, highlight STALE\n  riskx feed sync --epss CVE-2021-44228,CVE-2024-3094",
	}
	cmd.AddCommand(newFeedSyncCmd())
	cmd.AddCommand(newFeedListCmd())
	return cmd
}

func newFeedSyncCmd() *cobra.Command {
	var (
		fCache string
		fEPSS  string
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull verified feeds (KEV / EPSS) into the offline cache",
		Long: `sync downloads the CISA KEV catalog and (with --epss) FIRST EPSS scores
for the listed CVEs, writing provenance-tagged rows to the feed cache
(default ~/.riskx/feed.json). This is the only command that touches the
upstream catalogs; every other command reads the cached copy.`,
		Example: "  riskx feed sync\n  riskx feed sync --epss CVE-2021-44228,CVE-2024-3094\n  riskx feed sync --cache ./myfeed.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			path := feed.DefaultCachePath()
			if fCache != "" {
				path = fCache
			}
			c, err := feed.Open(path)
			if err != nil {
				return err
			}
			var warnings []string
			kevN, kevErr := c.SyncKEV()
			if kevErr != nil {
				warnings = append(warnings, "kev: "+kevErr.Error())
			} else {
				cmd.PrintErrf("note: KEV sync — %d entries cached from CISA catalog\n", kevN)
			}
			if fEPSS != "" {
				cves := splitKEVList(fEPSS)
				epssN, epssErr := c.SyncEPSS(cves)
				if epssErr != nil {
					warnings = append(warnings, "epss: "+epssErr.Error())
				} else {
					cmd.PrintErrf("note: EPSS sync — %d scores cached from FIRST\n", epssN)
				}
			}
			if werr := c.Save(); werr != nil {
				warnings = append(warnings, "save: "+werr.Error())
			}
			kev, epss := c.Count()
			meta.FinishedAt = meta.StartedAt
			return printer(cmd).EmitJSON(output.Result{
				Meta: meta,
				Payload: map[string]any{
					"cache_path": c.Path(),
					"cache": map[string]int{
						"kev":  kev,
						"epss": epss,
					},
				},
				Warnings: warnings,
			})
		},
	}
	cmd.Flags().StringVar(&fCache, "cache", "", "feed cache file (default ~/.riskx/feed.json)")
	cmd.Flags().StringVar(&fEPSS, "epss", "", "comma-separated CVEs for EPSS sync")
	return cmd
}

func newFeedListCmd() *cobra.Command {
	var (
		fCache string
		fStale bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cached feed entries (offline; no network call)",
		Long: `list prints every row of the offline feed cache: source, CVE,
descriptor, fetch time, and staleness. It makes no network request — the
cache is the authoritative offline copy.`,
		Example: "  riskx feed list\n  riskx feed list --stale    # show only STALE entries\n  riskx feed list --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			path := feed.DefaultCachePath()
			if fCache != "" {
				path = fCache
			}
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return errs.Input("feed.list", "no feed cache found",
					"run 'riskx feed sync' first; default cache is ~/.riskx/feed.json")
			}
			c, err := feed.Open(path)
			if err != nil {
				return err
			}
			rows := c.All()
			if fStale {
				kept := make([]feed.Entry, 0)
				for _, e := range rows {
					if e.Stale {
						kept = append(kept, e)
					}
				}
				rows = kept
			}
			filter := "all"
			if fStale {
				filter = "stale-only"
			}
			meta.FinishedAt = meta.StartedAt
			return printer(cmd).EmitJSON(output.Result{
				Meta: meta,
				Payload: map[string]any{
					"cache_path": c.Path(),
					"filter":     filter,
					"entries":    rows,
				},
			})
		},
	}
	cmd.Flags().StringVar(&fCache, "cache", "", "feed cache file (default ~/.riskx/feed.json)")
	cmd.Flags().BoolVar(&fStale, "stale", false, "show only STALE entries")
	return cmd
}

// splitKEVList splits a comma-separated CVE list, upper-cased and validated.
func splitKEVList(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(strings.ToUpper(s))
		if strings.HasPrefix(s, "CVE-") {
			out = append(out, s)
		}
	}
	return out
}
