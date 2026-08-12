// Delta scanning (delta-v1): snapshot diffing for continuous change
// detection. Evidence basis: Praetorian EASM lifecycle (fingerprinting ->
// change detection) and Gartner CTEM's continuous-monitoring stage; see
// /home/ubuntu/riskx-research/delta-scanning-design.md.

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/delta"
)

func newDeltaCmd() *cobra.Command {
	var fData, fSince string
	cmd := &cobra.Command{
		Use:   "delta",
		Short: "Diff the current evidence store against the prior scan snapshot",
		Long: `delta compares the two most recent scan snapshots stored in the
evidence store and reports the observed changes: new, gone, and changed assets
plus new, resolved, and changed findings. Every delta item carries the SHA-256
hashes of the compared content, so the output is auditable and reproducible.

Note: the evidence store is append-only (upsert by content ID), so persisted
assets never disappear from it; gone_asset and resolved_finding therefore
compare the stored SNAPSHOTS — a gone asset is one that a prior run observed
but the later stored run did not.

For a live diff against the current run's discovery output, use
'riskx discover --delta' instead.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, ok := resolveDataPath(fData)
			if !ok {
				return errs.Input("delta", "no evidence store path",
					"run with --data <db> or set RISKX_DATA")
			}
			s, err := openStore(path)
			if err != nil {
				return err
			}
			if s != nil {
				defer storeClose(s)
			}

			ids, err := s.ListDeltaSnapshotIDs()
			if err != nil {
				return err
			}
			if len(ids) < 2 {
				cmd.PrintErrf("delta: need at least two stored snapshots for a diff (found %d); run 'riskx discover --delta' twice\n", len(ids))
				return nil
			}
			// Default: diff the two most recent stored snapshots. --since
			// pins the older snapshot; its pair is the NEXT chronologically
			// stored snapshot (never the latest) so an out-of-band snapshot
			// added later cannot silently skew the comparison.
			var oldID, newID string
			if fSince != "" {
				oldID = fSince
				for i, id := range ids {
					if id == oldID && i+1 < len(ids) {
						newID = ids[i+1]
						break
					}
				}
				if newID == "" {
					return errs.Input("delta", fmt.Sprintf("snapshot %q has no later stored snapshot", oldID),
						"choose an earlier snapshot; the newest cannot be used with --since")
				}
			} else {
				oldID, newID = ids[len(ids)-2], ids[len(ids)-1]
			}
			load := func(id string) (*delta.Snapshot, error) {
				payload, err := s.DeltaSnapshotPayload(id)
				if err != nil {
					return nil, err
				}
				if payload == nil {
					return nil, errs.Input("delta", fmt.Sprintf("snapshot %q not found", id),
						"list snapshots with 'riskx assets' or use the latest stored IDs")
				}
				p := &delta.Snapshot{}
				if jerr := json.Unmarshal(payload, p); jerr != nil {
					return nil, errs.Wrap(errs.CodeInternal, "delta.unmarshal",
						"snapshot payload invalid", jerr)
				}
				p.NormalizeHashes()
				return p, nil
			}
			prior, err := load(oldID)
			if err != nil {
				return err
			}
			cur, err := load(newID)
			if err != nil {
				return err
			}
			items := delta.Diff(prior, cur.Assets, cur.Findings, cur.ID)

			summary := delta.Summary(items)
			meta := output.NewMeta("delta")
			meta.StartedAt = startedNow()
			meta.FinishedAt = meta.StartedAt
			if err := printer(cmd).EmitJSON(output.Result{Meta: meta,
				Payload: map[string]any{
					"since": oldID, "current": newID,
					"summary": summary, "changes": items,
				}}); err != nil {
				return err
			}
			cmd.PrintErrf("delta: %d change(s) between %s and %s\n",
				len(items), summaryText(summary), oldID)
			return nil
		},
	}
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"),
		"evidence store path (or 'off' to disable; env RISKX_DATA)")
	cmd.Flags().StringVar(&fSince, "since", "",
		"compare against this specific snapshot ID (default: latest stored)")
	return cmd
}

// summaryText renders a compact per-kind summary, e.g. "2 new, 1 gone".
func summaryText(summary map[delta.Kind]int) string {
	order := []struct {
		k delta.Kind
		s string
	}{
		{delta.KindNewAsset, "new asset"},
		{delta.KindGoneAsset, "gone"},
		{delta.KindChangedAsset, "changed asset"},
		{delta.KindNewFinding, "new finding"},
		{delta.KindResolvedFinding, "resolved"},
		{delta.KindChangedFinding, "changed finding"},
	}
	var parts []string
	for _, o := range order {
		if n, ok := summary[o.k]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, o.s))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
