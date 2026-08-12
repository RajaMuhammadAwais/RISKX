package main

import (
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/feed"
	"github.com/RajaMuhammadAwais/RISKX/internal/prioritize"
)

// --- prioritize ------------------------------------------------------------

// newPrioritizeCmd returns the "prioritize" command (rank-v1).
//
// Design (evidence, not guessing):
//   - ranking uses ONLY documented public exploitation evidence (CISA KEV,
//     FIRST EPSS) from the offline feed cache; no invented or interpolated
//     signals;
//   - findings with no public exploit evidence are ranked LAST and labeled
//     "no_exploit_evidence" — never promoted silently;
//   - every rank line carries the evidence row that produced it, so an
//     analyst can trace any rank back to public documentation.
func newPrioritizeCmd() *cobra.Command {
	var (
		fData  string
		fCache string
	)
	cmd := &cobra.Command{
		Use:   "prioritize",
		Short: "Rank stored findings by documented public exploit evidence",
		Long: `prioritize ranks the findings stored in the evidence database using
only documented public exploitation evidence: CISA KEV membership (confirmed
in-the-wild exploitation) and FIRST EPSS scores (published exploitation
probability). It is the evidence-backed answer to "what do I fix first?" —
findings with no public exploit evidence present are ranked last, and every
rank line carries the exact evidence (source URL, CVE, value) that produced it.

Requires a populated evidence store (--data or RISKX_DATA) and a feed cache
(run 'riskx feed sync' first). This is a purely local, offline command: the
feed cache is the authoritative copy.`,
		Example: "  riskx feed sync\n  riskx discover --domain example.com\n  riskx prioritize\n  riskx prioritize --data /var/lib/riskx/store.db --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()

			path, ok := resolveDataPath(fData)
			if !ok {
				return errs.Input("prioritize", "no evidence store configured",
					"set --data, env RISKX_DATA, or run 'riskx discover --data ...' first")
			}
			cachePath := feed.DefaultCachePath()
			if fCache != "" {
				cachePath = fCache
			}
			if _, err := os.Stat(cachePath); os.IsNotExist(err) {
				return errs.Input("prioritize", "feed cache not found",
					"run 'riskx feed sync' first; cache is at "+cachePath)
			}
			c, err := feed.Open(cachePath)
			if err != nil {
				return err
			}
			s, err := openStore(path)
			if err != nil {
				return err
			}
			defer storeClose(s)

			findings, err := s.ListFindings()
			if err != nil {
				return errs.Wrap(errs.CodeInternal, "prioritize", "cannot list findings", err)
			}
			if len(findings) == 0 {
				return errs.Input("prioritize", "no findings in the evidence store",
					"run 'riskx discover' or 'riskx scan' first to collect findings")
			}
			if !prioritize.HasCVEs(findings) {
				return errs.Input("prioritize", "findings carry no CVE references",
					"prioritize ranks using KEV/EPSS evidence; findings need CVE references (e.g. from 'riskx vuln' enrichment)")
			}

			ranks := prioritize.Rank(findings, c)
			var counts map[string]int
			counts = map[string]int{"actively_exploited": 0, "high_probability": 0, "no_exploit_evidence": 0}
			for _, r := range ranks {
				counts[r.Tier]++
			}

			meta.FinishedAt = time.Now().UTC()
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"rank_model": prioritize.RankModelVersion,
				"findings":   len(findings),
				"tiers":      counts,
				"ranked":     ranks,
			}})
		},
	}
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (or 'off' to disable; env RISKX_DATA)")
	cmd.Flags().StringVar(&fCache, "cache", "", "feed cache file (default ~/.riskx/feed.json)")
	return cmd
}
