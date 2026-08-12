package main

import (
	"encoding/json"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/idgen"
	"github.com/RajaMuhammadAwais/RISKX/internal/delta"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/mode"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/discovery/ctlog"
	"github.com/RajaMuhammadAwais/RISKX/internal/discovery/dns"
	"github.com/RajaMuhammadAwais/RISKX/internal/discovery/http"
	"github.com/RajaMuhammadAwais/RISKX/internal/discovery/tls"
	"github.com/RajaMuhammadAwais/RISKX/internal/risk"
	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/internal/vulnerability/findings"
	"github.com/RajaMuhammadAwais/RISKX/internal/vulnerability/ingest"
	"github.com/RajaMuhammadAwais/RISKX/internal/vulnerability/normalize"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// --- discover ------------------------------------------------------------

func newDiscoverCmd() *cobra.Command {
	var (
		fMode    string
		fRecords string
		fPorts   string
		fFile    string
		fData    string
		fCT      bool
		fDelta   bool
		allCTEv  []models.Evidence
	)
	cmd := &cobra.Command{
		Use:   "discover [targets...]",
		Short: "Passively discover assets for the given targets",
		Long: `Discover resolves domains, enumerates DNS records, inspects HTTP and
TLS surfaces, and (with --ports) probes configured TCP ports. All discovery is
read-only (PASSIVE by default). Results include per-asset provenance: how the
asset was found, when, and with what confidence. Detection without evidence
reports 'insufficient' confidence rather than guessing.`,
			Example: "  riskx discover example.com\n  riskx discover example.com --records A,MX,TXT --ports 80,443,8080\n  riskx discover example.com --ct",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mode.Parse(fMode)
			if err != nil {
				return err
			}
			if m != mode.Passive && m != mode.Safe {
				return errs.New(errs.CodeModeDenied, "discover",
					"discover supports passive and safe modes only; intrusive scanning is not a discovery activity")
			}
			started := startedNow()
			targets := loadTargets(args, fFile)
			if len(targets) == 0 {
				return errs.Input("discover", "no targets provided",
					"pass targets as arguments or via --file")
			}
			var assets []models.Asset
			allCTEv = nil
			for _, t := range targets {
				a, err := discoverOne(cmd.Context(), t, fRecords, fPorts, m)
				if err != nil {
					cmd.PrintErrf("warning: target %s: %v\n", t, err)
					continue
				}
				assets = append(assets, a...)
				// Certificate-transparency enumeration (opt-in via --ct):
				// pure observation of public CT logs — zero packets sent to the
				// target. Wildcard SANs are reported AS-IS, never expanded.
				if fCT {
					ctAssets, ev, vis, err := ctlog.Discover(cmd.Context(), nil, t)
					if err != nil {
						cmd.PrintErrf("warning: ct enumeration for %s: %v (providers: %v)\n", t, err, vis)
					} else {
						assets = append(assets, ctAssets...)
						allCTEv = append(allCTEv, ev...)
						if len(vis) > 0 {
							cmd.PrintErrf("note: ct visibility for %s: %v\n", t, vis)
						}
					}
				}
			}
			meta := output.NewMeta(string(m))
			meta.StartedAt = started
			meta.FinishedAt = started
			// Persist discovered assets to the evidence store when --data is
			// given (storage-v1; schema storage-v1). Persistence failures are
			// reported as warnings, never fatal: the run's evidence output is
			// the primary deliverable.
					if path, ok := resolveDataPath(fData); ok {
					s, serr := openStore(path)
					if serr == nil {
						putAssets(cmd, s, assets)
						if len(allCTEv) > 0 {
							putEvidence(cmd, s, allCTEv)
						}
						if fDelta {
							deltaRun(cmd, s, assets, allCTEv)
						}
						storeClose(s)
					} else {
						cmd.PrintErrf("warning: evidence store not written: %v\n", serr)
					}
				}
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{"assets": assets}})
		},
	}
	cmd.Flags().StringVar(&fMode, "mode", "passive", "discovery mode (passive|safe)")
	cmd.Flags().StringVar(&fRecords, "records", "A,AAAA,CNAME,MX,NS,TXT", "comma-separated DNS record types")
	cmd.Flags().StringVar(&fPorts, "ports", "", "comma-separated TCP ports to probe (connect only)")
	cmd.Flags().StringVar(&fFile, "file", "", "file of targets, one per line")
	cmd.Flags().BoolVar(&fCT, "ct", false, "add certificate-transparency enumeration (public CT logs; passive)")
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (or 'off' to disable; env RISKX_DATA)")
	cmd.Flags().BoolVar(&fDelta, "delta", false, "snapshot this run and print changes vs the prior run (requires --data)")
	return cmd
}

func discoverOne(ctx context.Context, target string, records, ports string, m mode.SecurityMode) ([]models.Asset, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, errs.Input("discover.one", "empty target", "")
	}
	var assets []models.Asset
	// DNS enumeration
	recs := splitCSV(records)
	dnsAssets, err := dns.Enumerate(ctx, t, recs)
	if err != nil {
		return nil, fmt.Errorf("dns enumeration: %w", err)
	}
	assets = append(assets, dnsAssets...)
	// HTTP surface
	httpAssets, err := http.Inspect(ctx, t)
	if err != nil {
		// HTTP absence is recorded, not fatal (internal targets may not speak HTTP).
		fmt.Printf("note: http inspection skipped for %s: %v\n", t, err)
	} else {
		assets = append(assets, httpAssets...)
	}
	// TLS certificate surface
	tlsAssets, err := tls.Inspect(ctx, t)
	if err != nil {
		fmt.Printf("note: tls inspection skipped for %s: %v\n", t, err)
	} else {
		assets = append(assets, tlsAssets...)
	}
	// Optional TCP connect probes (connect-only; respects mode)
	if ports != "" {
		portAssets, err := probePorts(ctx, t, ports, m)
		if err != nil {
			fmt.Printf("note: port probing skipped for %s: %v\n", t, err)
		} else {
			assets = append(assets, portAssets...)
		}
	}
	for i := range assets {
		if assets[i].ID == "" {
			assets[i].ID = idgen.AssetID(assets[i].Kind, assets[i].Value, assets[i].Host, assets[i].Port)
		}
		assets[i].Schema = models.SchemaAsset
	}
	return assets, nil
}

// --- assets --------------------------------------------------------------

func newAssetsCmd() *cobra.Command {
	var fData string
	cmd := &cobra.Command{
		Use:   "assets",
		Short: "List and inspect the local asset inventory",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List inventory assets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, ok := resolveDataPath(fData)
			if !ok {
				fmt.Println("asset inventory: no evidence store configured for this run")
				fmt.Println("set --data, env RISKX_DATA, or run 'riskx discover --data ...' first.")
				return nil
			}
			s, err := openStore(path)
			if err != nil {
				return fmt.Errorf("open evidence store: %w", err)
			}
			defer storeClose(s)
			assets, err := s.ListAssets()
			if err != nil {
				return fmt.Errorf("list assets: %w", err)
			}
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			meta.FinishedAt = meta.StartedAt
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{"assets": assets}})
		},
	}
	list.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	cmd.AddCommand(list)
	return cmd
}

// putAssets writes discovered assets to the store, logging the count written.
func putEvidence(cmd *cobra.Command, s *storage.Store, items []models.Evidence) {
	if err := s.PutEvidence(items, "", ""); err != nil {
		cmd.PrintErrf("warning: evidence rows not written: %v\n", err)
	}
}

func putAssets(cmd *cobra.Command, s *storage.Store, assets []models.Asset) {
	if s == nil || len(assets) == 0 {
		return
	}
	n, err := s.PutAssets(assets)
	if err != nil {
		cmd.PrintErrf("warning: persisting assets: %v\n", err)
		return
	}
	cmd.PrintErrf("stored %d asset record(s) (%s)\n", n, storage.SchemaVersion())
}

// deltaRun snapshots the current run and diffs it against the prior stored
// snapshot (delta-v1). No-op without --delta; snapshot store failures warn
// but never fail the run — the primary deliverable is the discovery output.
func deltaRun(cmd *cobra.Command, s *storage.Store, assets []models.Asset, ctEv []models.Evidence) {
	if s == nil {
		return
	}
	// Snapshot ID is content-addressed from the run's discovery inputs so
	// identical runs reproduce identical snapshot IDs (spec §27, §43).
	snapID := idgen.SnapshotID("run", assets)
	snap := delta.NewSnapshot(snapID, assets, nil)
	b, err := json.Marshal(snap)
	if err != nil {
		cmd.PrintErrf("warning: delta snapshot: %v\n", err)
		return
	}
	if perr := s.PutDeltaSnapshot(snapID, json.RawMessage(b), snap.TakenAt); perr != nil {
		cmd.PrintErrf("warning: delta snapshot: %v\n", perr)
		return
	}
	ids, ierr := s.ListDeltaSnapshotIDs()
	if ierr != nil {
		cmd.PrintErrf("warning: delta snapshot: %v\n", ierr)
		return
	}
	var prior *delta.Snapshot
	// Skip the snapshot just stored (last element) when resolving the prior.
	if len(ids) > 1 {
		payload, perr := s.DeltaSnapshotPayload(ids[len(ids)-2])
		if perr == nil && payload != nil {
			p := &delta.Snapshot{}
			if json.Unmarshal(payload, p) == nil {
				p.NormalizeHashes()
				prior = p
			}
		}
	}
	if prior == nil {
		cmd.PrintErrf("delta: snapshot %s stored (first run for these targets; run again to see changes)\n", snapID)
		return
	}
	items := delta.Diff(prior, assets, nil, snapID)
	cmd.PrintErrf("delta: snapshot %s — %s\n", snapID, summaryText(delta.Summary(items)))
	for _, it := range items {
		cmd.PrintErrf("  %s: %s (label=%q", it.Kind, it.ID, it.Label)
		if len(it.Changes) > 0 {
			cmd.PrintErrf(", changes=%v", it.Changes)
		}
		cmd.PrintErrf(")\n")
	}
}

// --- scan ----------------------------------------------------------------

func newScanCmd() *cobra.Command {
	var fMode, fCI, fPreapprove string
	cmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Run a scan: discover + enrich + risk-score (alias flow)",
		Long: `scan runs discover, then vulnerability enrichment, then risk scoring.
It is a convenience flow over the individual commands. Intrusive steps require
--mode active or --mode validation plus explicit authorization (--preapprove in CI).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mode.Parse(fMode)
			if err != nil {
				return err
			}
			auth := mode.DefaultAuthorizer(fCI != "", fPreapprove != "")
			if err := auth.Require(m, nil); err != nil {
				return err
			}
			fmt.Printf("scan flow (%s mode): targets=%v\n", m, args)
			fmt.Println("phase 2/3 pipelines (vuln enrichment + risk scoring) wire into scan in Phase 3/4.")
			return nil
		},
	}
	cmd.Flags().StringVar(&fMode, "mode", "passive", "scan mode")
	cmd.Flags().StringVar(&fCI, "ci", "", "run in CI mode (deterministic output; --preapprove required for intrusive modes)")
	cmd.Flags().StringVar(&fPreapprove, "preapprove", "", "pre-approve the printed action plan (CI only)")
	return cmd
}

// --- vuln ----------------------------------------------------------------

func newVulnCmd() *cobra.Command {
	var fData string
	cmd := &cobra.Command{
		Use:   "vuln [cve...]",
		Short: "Look up and enrich vulnerability identifiers",
		Long: `vuln enriches CVE identifiers from verified feeds (KEV, NVD API 2.0,
EPSS, OSV) and reports per-source provenance and staleness. NVD outputs carry
the required NVD attribution.`,
		Example: "  riskx vuln CVE-2021-44228 CVE-2024-3094",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			output.AddNVDAttribution(&meta)

			sources := normalize.Sources{
				KEV: ingest.NewKEVClient(),
				NVD: ingest.NewNVDClient(""),
				EPSS: ingest.NewEPSSClient(),
				OSV: ingest.NewOSVClient(),
			}
			gen := findings.NewGenerator(sources)
			asset := models.Asset{
				ID:    idgen.AssetID("vuln-lookup"),
				Value: strings.Join(args, ","),
				Kind:  models.KindHost,
			}
			var vulns []normalize.Vulnerability
			var findingsOut []models.Finding
			var evidences []models.Evidence
			for _, id := range args {
				id = strings.TrimSpace(strings.ToUpper(id))
				if !strings.HasPrefix(id, "CVE-") {
					return errs.Input("vuln", fmt.Sprintf("unsupported identifier %q", id),
						"riskx vuln currently accepts CVE IDs only (Phase 3)")
				}
				v, err := normalize.Fuse(cmd.Context(), sources, id)
				if err != nil {
					return err
				}
				vulns = append(vulns, v)
				f, evs, ferr := gen.CVEFinding(cmd.Context(), asset, id)
				if ferr != nil {
					return ferr
				}
				if f != nil {
					findingsOut = append(findingsOut, *f)
					evidences = append(evidences, evs...)
				}
			}
				meta.FinishedAt = time.Now().UTC()
			// Persist findings + evidence to the store when --data is given.
			// Finding/evidence writes are content-addressed (dedup by ID);
			// failures warn but never drop the primary JSON output.
			if path, ok := resolveDataPath(fData); ok {
				s, serr := openStore(path)
				if serr == nil {
					persistFindings(cmd, s, findingsOut, evidences)
					storeClose(s)
				} else {
					cmd.PrintErrf("warning: evidence store not written: %v\n", serr)
				}
			}
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"vulnerabilities": vulns,
				"findings":        findingsOut,
				"evidence":        evidences,
			}})
		},
	}
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (or 'off' to disable; env RISKX_DATA)")
	return cmd
}

// persistFindings stores findings and their evidence chain.
func persistFindings(cmd *cobra.Command, s *storage.Store, findingsOut []models.Finding, evidences []models.Evidence) {
	if s == nil || len(findingsOut) == 0 {
		return
	}
	if err := s.PutFindings(findingsOut); err != nil {
		cmd.PrintErrf("warning: persisting findings: %v\n", err)
		return
	}
	var stored int
	for _, f := range findingsOut {
		// Each finding carries its own evidence chain (models.Finding.Evidence);
		// persist the finding's chain, not the run-wide slice (per-finding scope).
		items := f.Evidence
		if err := s.PutEvidence(items, f.ID, f.AssetID); err != nil {
			cmd.PrintErrf("warning: persisting evidence for %s: %v\n", f.ID, err)
			continue
		}
		stored++
	}
	cmd.PrintErrf("stored %d finding record(s) (%s)\n", stored, storage.SchemaVersion())
}

// --- risk ----------------------------------------------------------------

func newRiskCmd() *cobra.Command {
	var fData string
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Compute risk-v1 scores for assets",
		Long: `risk computes deterministic risk-v1 scores. Every score prints its
factor table, weights, evidence, and model version. Missing evidence caps
factors at zero and is listed in incomplete_inputs; stale feeds are listed in
stale_inputs. With --data, risk scores the stored asset inventory (exposure
from stored provenance; centrality/identity/standards-gap remain incomplete
until Phase 6/8/10 land — never guessed).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			eng, err := risk.NewEngine(nil)
			if err != nil {
				return err
			}
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			var scores []models.RiskScore
			var warns []string
			path, storeOk := resolveDataPath(fData)
			if storeOk {
				s, serr := openStore(path)
				if serr == nil {
					assets, aerr := s.ListAssets()
					if aerr == nil {
						for _, a := range assets {
							bundle := assetBundle(a)
							sc := eng.Score(bundle)
							scores = append(scores, sc)
							if s.PutRiskScore(sc) != nil {
								cmd.PrintErrf("warning: persisting score for %s\n", sc.AssetID)
							}
						}
					} else {
						cmd.PrintErrf("warning: listing assets: %v\n", aerr)
					}
					storeClose(s)
				} else {
					cmd.PrintErrf("warning: evidence store not read: %v\n", serr)
				}
			}
			if len(scores) == 0 {
				// No store configured or empty: fall back to a documented demo
				// input with only explicitly-stated evidence — the same
				// contract as stored scoring, made obvious in output.
				warns = []string{"no evidence store; scoring an explicit demo input"}
				sc := eng.Score(risk.InputBundle{
					AssetID:     idgen.AssetID("demo-asset"),
					Exposure:    models.ExposureInternet,
					KEV:         true,
					Criticality: 0.8,
				})
				scores = []models.RiskScore{sc}
			}
			meta.FinishedAt = time.Now().UTC()
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{"scores": scores}, Warnings: warns})
		},
	}
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (or 'off' to disable; env RISKX_DATA)")
	return cmd
}

// assetBundle derives a scoring InputBundle from a stored asset using only its
// stored evidence. Centrality, privilege, and standards-gap inputs are left
// nil (incomplete_inputs in the score) rather than guessed.
func assetBundle(a models.Asset) risk.InputBundle {
	b := risk.InputBundle{
		AssetID:   a.ID,
		Exposure:  a.Exposure,
		Evidence:  nil,
		StaleInputs: nil,
	}
	if a.Criticality != "" {
		// Criticality is stored as a string; parse only well-formed 0..1 values.
		if n, err := strconv.ParseFloat(strings.TrimSpace(a.Criticality), 64); err == nil && n >= 0 && n <= 1 {
			b.Criticality = n
		}
	}
	return b
}
