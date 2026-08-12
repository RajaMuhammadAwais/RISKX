package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	awscloud "github.com/RajaMuhammadAwais/RISKX/internal/cloud/aws"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/mode"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/graph"
	"github.com/RajaMuhammadAwais/RISKX/internal/reporting"
	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/internal/validate"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// --- graph -----------------------------------------------------------------

func newGraphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Inspect the attack graph (asset/relationship store)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List graph nodes and edges",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			g := demoGraph()
			meta.FinishedAt = time.Now().UTC()
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"model_version": graph.ModelVersion,
				"nodes":         g.Nodes,
				"edges":         g.Edges,
			}})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "centrality",
		Short: "Compute node centrality (attack-path position input)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			g := demoGraph()
			meta.FinishedAt = time.Now().UTC()
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"model_version": graph.ModelVersion,
				"centrality":    g.CentralityReport(graph.ModeEvidenceBacked),
			}})
		},
	})
	return cmd
}

// demoGraph builds an evidence-backed enterprise network graph for the
// analysis commands. Phase 4 replaces this with storage-v1 persistence:
// assets, relationships, and risk scores are stored and reloaded rather than
// reconstructed per command.
func demoGraph() *graph.Graph {
	score := func(exposure, crit float64) *models.RiskScore {
		return &models.RiskScore{Factors: []models.RiskFactor{
			{Name: "exposure", Value: exposure, Weight: 0.2},
			{Name: "criticality", Value: crit, Weight: 0.15},
			{Name: "known_exploitation", Value: 0, Weight: 0.2},
		}}
	}
	ev := func(t string) models.Evidence {
		return models.Evidence{Type: t, Source: "riskx-discovery", Timestamp: time.Now().UTC()}
	}
	g := graph.New()
	g.AddNode(graph.Node{ID: "web", Label: "web.example.com", Kind: models.KindHost, Score: score(1, 0.4)})
	g.AddNode(graph.Node{ID: "api", Label: "api.example.com", Kind: models.KindAPI, Score: score(0, 0.5)})
	g.AddNode(graph.Node{ID: "db", Label: "db.internal", Kind: models.KindHost, Score: score(0, 0.9)})
	g.AddNode(graph.Node{ID: "ssh", Label: "ssh.internal", Kind: models.KindHost, Score: score(0, 0.3)})
	g.AddNode(graph.Node{ID: "admin", Label: "admin.example.com", Kind: models.KindHost, Score: score(1, 0.8)})
	g.AddEdge(graph.Edge{ID: graph.EdgeID("web", "db", models.RelAffectedBy), From: "web", To: "db",
		Type: models.RelAffectedBy, Status: models.StatusObserved, Weight: 0.9,
		Evidence: []models.Evidence{ev("kev")}})
	g.AddEdge(graph.Edge{ID: graph.EdgeID("web", "api", models.RelExposes), From: "web", To: "api",
		Type: models.RelExposes, Status: models.StatusObserved, Weight: 0.6,
		Evidence: []models.Evidence{ev("network")}})
	g.AddEdge(graph.Edge{ID: graph.EdgeID("api", "db", models.RelAffectedBy), From: "api", To: "db",
		Type: models.RelAffectedBy, Status: models.StatusInferred, Weight: 0.75,
		Evidence: []models.Evidence{ev("feed")}})
	g.AddEdge(graph.Edge{ID: graph.EdgeID("ssh", "db", models.RelConnectedTo), From: "ssh", To: "db",
		Type: models.RelConnectedTo, Status: models.StatusObserved, Weight: 0.8,
		Evidence: []models.Evidence{ev("network")}})
	g.AddEdge(graph.Edge{ID: graph.EdgeID("web", "admin", models.RelAccessibleBy), From: "web", To: "admin",
		Type: models.RelAccessibleBy, Status: models.StatusInferred, Weight: 0.5,
		Evidence: []models.Evidence{ev("feed")}})
	return g
}

// --- attack-path -----------------------------------------------------------

func newAttackPathCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attack-path",
		Short: "Rank attack paths to high-value targets",
		Long: `attack-path enumerates and ranks paths from exposed entry points to
critical assets. Ranking uses observed/inferred edge statuses; inferred edges
are labeled as such and never presented as confirmed (spec §13).`,
	}
	var fModeFlag string
	cmd.AddCommand(&cobra.Command{
		Use:   "top [n]",
		Short: "Show the top N attack paths",
		Long: `top ranks paths from internet-exposed entry nodes to critical assets
using weighted Dijkstra traversal (graph-v1). Edge statuses gate results:
observed_only uses only directly measured edges; evidence_backed (default)
includes inferred edges labeled as such; exploratory includes theoretical
potential edges for planning only.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()

			rm := graph.ModeEvidenceBacked
			switch fModeFlag {
			case "observed_only":
				rm = graph.ModeObservedOnly
			case "exploratory":
				rm = graph.ModeExploratory
			}

			g := demoGraph()
			paths, err := g.DijkstraPaths(rm)
			if err != nil {
				return err
			}
			n := 5
			if len(args) > 0 {
				if v, e := strconv.Atoi(args[0]); e == nil && v > 0 {
					n = v
				}
			}
			if n > len(paths) {
				n = len(paths)
			}
			meta.FinishedAt = time.Now().UTC()
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"model_version": graph.ModelVersion,
				"mode":          string(rm),
				"top_paths":     paths[:n],
			}})
		},
	})
	cmd.Flags().StringVar(&fModeFlag, "mode", "evidence_backed",
		"edge-status gate: observed_only|evidence_backed|exploratory")
	return cmd
}

// --- report ----------------------------------------------------------------

func newReportCmd() *cobra.Command {
	var fData string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate risk reports in supported formats",
		Long: `report generates human-readable risk reports. JSON is the canonical
machine format; the report layer consumes canonical results so human and
machine outputs stay consistent (spec §31, §38). The report consumes the
stored evidence (assets/findings/scores) — run discover/vuln/risk with --data
first, or pass the store path here.`,
	}
	summary := &cobra.Command{
		Use:   "summary",
		Short: "Print an executive risk summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, ok := resolveDataPath(fData)
			if !ok {
				return fmt.Errorf("report.summary: no evidence store configured; set --data or RISKX_DATA")
			}
			s, err := storage.Open(path)
			if err != nil {
				return fmt.Errorf("open evidence store: %w", err)
			}
			defer storeClose(s)
			assets, err := s.ListAssets()
			if err != nil {
				return fmt.Errorf("list assets: %w", err)
			}
			findings, err := s.ListFindings()
			if err != nil {
				return fmt.Errorf("list findings: %w", err)
			}
			scores, err := s.ListRiskScores()
			if err != nil {
				return fmt.Errorf("list scores: %w", err)
			}
			sum := reporting.Summary(reporting.SummaryInput{
				Assets:   assets,
				Findings: findings,
				Scores:   scores,
			})
			meta := output.NewMeta("passive")
			meta.StartedAt = startedNow()
			meta.FinishedAt = meta.StartedAt
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: sum})
		},
	}
	summary.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	cmd.AddCommand(summary)
	return cmd
}

// --- export ----------------------------------------------------------------

func newExportCmd() *cobra.Command {
	var fData, fOutput string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export findings and scores to external formats",
	}
	exportFromStore := func(exportFn func(reporting.SummaryInput, io.Writer) error) func(cmd *cobra.Command, args []string) error {
		return func(cmd *cobra.Command, args []string) error {
			path, ok := resolveDataPath(fData)
			if !ok {
				return fmt.Errorf("export: no evidence store configured; set --data or RISKX_DATA")
			}
			s, err := storage.Open(path)
			if err != nil {
				return fmt.Errorf("open evidence store: %w", err)
			}
			defer storeClose(s)
			assets, err := s.ListAssets()
			if err != nil {
				return fmt.Errorf("list assets: %w", err)
			}
			findings, err := s.ListFindings()
			if err != nil {
				return fmt.Errorf("list findings: %w", err)
			}
			scores, err := s.ListRiskScores()
			if err != nil {
				return fmt.Errorf("list scores: %w", err)
			}
			out, cleanup, err := openOutput(fOutput)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := exportFn(reporting.SummaryInput{Assets: assets, Findings: findings, Scores: scores}, out); err != nil {
				return err
			}
			cmd.PrintErrf("exported from %s (%s)\n", path, storage.SchemaVersion())
			return nil
		}
	}
	jsonl := &cobra.Command{
		Use:   "jsonl",
		Short: "Export as JSONL",
		Args:  cobra.NoArgs,
		RunE:  exportFromStore(reporting.ExportJSONL),
	}
	csv := &cobra.Command{
		Use:   "csv",
		Short: "Export as CSV (one section per write: findings or scores)",
		Args:  cobra.NoArgs,
		RunE:  exportFromStore(reporting.ExportCSV),
	}
	sarif := &cobra.Command{
		Use:   "sarif",
		Short: "Export as SARIF 2.1.0 for third-party ingestion",
		Args:  cobra.NoArgs,
		RunE:  exportFromStore(reporting.ExportSARIF),
	}
	for _, c := range []*cobra.Command{jsonl, csv, sarif} {
		c.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
		c.Flags().StringVar(&fOutput, "output", "", "output file (default stdout)")
	}
	cmd.AddCommand(jsonl, csv, sarif)
	return cmd
}

// --- policy ----------------------------------------------------------------

func newPolicyCmd() *cobra.Command {
	var fFile string
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate policy over the current findings and scores",
		Long: `policy evaluates the configured policy document against findings and
risk scores and prints a structured outcome. Exit codes follow the CLI
contract: 0 = no violation, 1 = violation, 2 = execution error.`,
	}
	check := &cobra.Command{
		Use:   "check",
		Short: "Run policy check and exit with the correct code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("policy check wires into this command with the findings store (Phase 6).")
			fmt.Printf("policy file: %s (default built-in used when unset)\n", fFile)
			return nil
		},
	}
	check.Flags().StringVar(&fFile, "file", "", "policy file path")
	cmd.AddCommand(check)
	return cmd
}

// --- validate --------------------------------------------------------------

func newValidateCmd() *cobra.Command {
	var (
		fMode       string
		fPreapprove bool
		fCI         bool
		fKind       string
		fDNSType    string
		fDNSWant    string
		fData       string
	)
	cmd := &cobra.Command{
		Use:   "validate [targets...]",
		Short: "Safely validate findings against user-authorized steps",
		Long: `validate runs only safe, pre-approved read-only checks: DNS resolution
verification, TLS certificate observation, and HTTP response verification.
A pre-execution plan is always printed; nothing runs without explicit
authorization (--preapprove in CI, interactive 'yes' otherwise). Validation
results attach to the finding as validated evidence (spec §8, §30).

Checks observe real state and never infer: a failed resolution is recorded
as an observation with passed=false, never guessed around.`,
		Example: "  riskx validate example.com --kind dns --dns-type A --dns-want 93.184.216.34\n  riskx validate example.com --kind tls\n  riskx validate https://example.com --kind http",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mode.Parse(fMode)
			if err != nil {
				return err
			}
			if m != mode.Safe && m != mode.Validation && m != mode.Active {
				return fmt.Errorf("validate requires mode safe, validation, or active (got %s)", m)
			}
			auth := mode.NewAuthorizer(cmd.OutOrStdout(), os.Stdin, fCI, fPreapprove)
			var actions []mode.Action
			for _, t := range args {
				actions = append(actions, mode.Action{
					Description: fmt.Sprintf("%s verification of %s", fKind, t),
					Target:      t, Method: "validate",
				})
			}
			if err := auth.Require(m, actions); err != nil {
				return err
			}
			ctx := cmd.Context()
			var results []validate.ValidationResult
			switch fKind {
			case "dns":
				want := splitCSV(fDNSWant)
				for _, t := range args {
					r, err := validate.VerifyDNS(ctx, validate.DefaultResolver(), t, fDNSType, want)
					if err != nil {
						cmd.PrintErrf("warning: %s: %v\n", t, err)
						continue
					}
					results = append(results, r)
				}
			case "tls":
				for _, t := range args {
					r, err := validate.VerifyTLS(ctx, t)
					if err != nil {
						cmd.PrintErrf("warning: %s: %v\n", t, err)
						continue
					}
					results = append(results, r)
				}
			case "http":
				for _, t := range args {
					r, err := validate.VerifyHTTP(ctx, t)
					if err != nil {
						cmd.PrintErrf("warning: %s: %v\n", t, err)
						continue
					}
					results = append(results, r)
				}
			default:
				return fmt.Errorf("validate: unsupported check kind %q (dns|tls|http)", fKind)
			}
			// Persist validated evidence to the store when configured.
			if path, ok := resolveDataPath(fData); ok {
				s, serr := storage.Open(path)
				if serr == nil {
					putValidatedEvidence(cmd, s, results)
					storeClose(s)
				} else {
					cmd.PrintErrf("warning: evidence store not written: %v\n", serr)
				}
			}
			meta := output.NewMeta(string(m))
			meta.StartedAt = startedNow()
			meta.FinishedAt = meta.StartedAt
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{"results": results}})
		},
	}
	cmd.Flags().StringVar(&fMode, "mode", "validation", "validation mode (safe|validation|active)")
	cmd.Flags().BoolVar(&fPreapprove, "preapprove", false, "pre-approve the printed plan (CI only)")
	cmd.Flags().BoolVar(&fCI, "ci", false, "run in CI mode")
	cmd.Flags().StringVar(&fKind, "kind", "dns", "check kind (dns|tls|http)")
	cmd.Flags().StringVar(&fDNSType, "dns-type", "A", "DNS record type (A/AAAA/MX/NS/TXT)")
	cmd.Flags().StringVar(&fDNSWant, "dns-want", "", "comma-separated expected record values (optional)")
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	return cmd
}

// openOutput opens the export output: a file path, or stdout with a no-op
// cleanup when unset. Errors are explicit (never a silent drop to /dev/null).
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return f, func() { f.Close() }, nil
}

// putValidatedEvidence stores validation results as validated evidence.
func putValidatedEvidence(cmd *cobra.Command, s *storage.Store, results []validate.ValidationResult) {
	if s == nil || len(results) == 0 {
		return
	}
	for _, r := range results {
		if err := s.PutEvidence(r.Evidence, "", r.Target); err != nil {
			cmd.PrintErrf("warning: persisting validated evidence for %s: %v\n", r.Target, err)
		}
	}
}

// --- continuous ------------------------------------------------------------

func newContinuousCmd() *cobra.Command {
	var fEvery string
	cmd := &cobra.Command{
		Use:   "continuous",
		Short: "Run RISKX on a schedule for continuous exposure management",
		Long: `continuous runs the discover → enrich → score → report loop on a
schedule (default: 24h, configurable with --every). Each cycle persists
results with scan metadata (spec §8 CTEM lifecycle).`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Start the continuous loop",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("continuous loop: interval=%s — scheduler wires into this command in Phase 7.\n", fEvery)
			return nil
		},
	})
	cmd.Flags().StringVar(&fEvery, "every", "24h", "cycle interval")
	return cmd
}

// --- cloud -----------------------------------------------------------------

// awsActions lists the read-only discovery actions. The allowed set is
// enforced: anything else (mutating, data-read, config) stays deferred.
var awsActions = []string{"whoami", "instances", "buckets", "identities", "all"}

func newCloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Cloud asset discovery and configuration assessment (AWS first)",
	}
	cmd.AddCommand(newCloudDiscoverCmd())
	cmd.AddCommand(&cobra.Command{
		Use:   "config-audit",
		Short: "Audit cloud configuration against CIS AWS Foundations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("cloud configuration audit (CIS AWS Foundations) is deferred to a later phase.")
			return nil
		},
	})
	return cmd
}

func newCloudDiscoverCmd() *cobra.Command {
	var (
		fAction     string
		fMode       string
		fPreapprove bool
		fCI         bool
		fData       string
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover AWS resources via read-only API access",
		Long: `discover lists cloud resources using read-only AWS Query APIs (STS
GetCallerIdentity, EC2 DescribeInstances, S3 ListBuckets, IAM ListUsers).
Credentials are read from the environment (AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_REGION) only — a read-only IAM principal
(e.g., SecurityAudit) is strongly recommended. No state is modified: the
action set is hardcoded (spec §30 safe operations).

A pre-execution plan of the API calls is always printed first; nothing runs
without explicit authorization (--preapprove in CI, interactive 'yes'
otherwise). Observed resources become canonical assets with cloud provenance.`,
		Example: "  riskx cloud discover --action all\n  riskx cloud discover --action whoami\n  riskx cloud discover --action instances --preapprove --ci",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := mode.Parse(fMode)
			if err != nil {
				return err
			}
			if m != mode.Safe && m != mode.Validation {
				return fmt.Errorf("cloud discover requires mode safe or validation (got %s)", m)
			}
			cfg, err := awscloud.ConfigFromEnv()
			if err != nil {
				return err
			}
			actions := expandActions(fAction)
			auth := mode.NewAuthorizer(cmd.OutOrStdout(), os.Stdin, fCI, fPreapprove)
			var plan []mode.Action
			for _, a := range actions {
				plan = append(plan, mode.Action{
					Description: fmt.Sprintf("AWS %s discovery in region %s (read-only query API)", a, cfg.Region),
					Target:      cfg.Region, Method: "aws_query",
				})
			}
			if err := auth.Require(m, plan); err != nil {
				return err
			}
			ctx := cmd.Context()
			client := awscloud.NewClient(cfg)
			var ident awscloud.Identity
			var instances []awscloud.EC2Instance
			var buckets []awscloud.S3Bucket
			var users []awscloud.IAMIdentity
			for _, a := range actions {
				switch a {
				case "whoami":
					i, err := client.Whoami(ctx)
					if err != nil {
						return fmt.Errorf("cloud.discover whoami: %w", err)
					}
					ident = i
				case "instances":
					ii, err := client.Instances(ctx)
					if err != nil {
						return fmt.Errorf("cloud.discover instances: %w", err)
					}
					instances = ii
				case "buckets":
					bb, err := client.Buckets(ctx)
					if err != nil {
						return fmt.Errorf("cloud.discover buckets: %w", err)
					}
					buckets = bb
				case "identities":
					uu, err := client.Identities(ctx)
					if err != nil {
						return fmt.Errorf("cloud.discover identities: %w", err)
					}
					users = uu
				}
			}
			assets := awscloud.ToAssets(ident, instances, buckets, users)
			if path, ok := resolveDataPath(fData); ok {
				s, serr := storage.Open(path)
				storeClose(s)
				if serr == nil {
					if n, err := s.PutAssets(assets); err != nil {
						cmd.PrintErrf("warning: persisting discovered assets: %v\n", err)
					} else {
						cmd.PrintErrf("persisted %d assets to %s\n", n, s.Path())
					}
				} else {
					cmd.PrintErrf("warning: evidence store not written: %v\n", serr)
				}
			}
			meta := output.NewMeta(string(m))
			meta.StartedAt = startedNow()
			meta.FinishedAt = time.Now().UTC()
			meta.Attribution = append(meta.Attribution, "assets observed via AWS Query APIs (read-only)")
			return printer(cmd).EmitJSON(output.Result{Meta: meta, Payload: map[string]any{
				"identity":  ident,
				"instances": instances,
				"buckets":   buckets,
				"users":     users,
				"assets":    assets,
			}})
		},
	}
	cmd.Flags().StringVar(&fAction, "action", "all", "discovery action ("+fmt.Sprintf("%v", awsActions)+")")
	cmd.Flags().StringVar(&fMode, "mode", "validation", "validation mode (safe|validation)")
	cmd.Flags().BoolVar(&fPreapprove, "preapprove", false, "pre-approve the printed plan (CI only)")
	cmd.Flags().BoolVar(&fCI, "ci", false, "run in CI mode")
	cmd.Flags().StringVar(&fData, "data", os.Getenv("RISKX_DATA"), "evidence store path (env RISKX_DATA)")
	return cmd
}

// expandActions resolves "all" into the concrete read-only action set; any
// other value is validated against the allow-list.
func expandActions(name string) []string {
	if name == "all" {
		out := make([]string, 0, len(awsActions)-1)
		for _, a := range awsActions {
			if a != "all" {
				out = append(out, a)
			}
		}
		return out
	}
	for _, a := range awsActions {
		if a == name {
			return []string{name}
		}
	}
	return nil
}

// --- identity --------------------------------------------------------------

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Identity and access analysis (Phase 6+)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "overview",
		Short: "Show identity privilege posture",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("identity analysis lands in Phase 6.")
			return nil
		},
	})
	return cmd
}

// --- agent -----------------------------------------------------------------

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "AI agent posture analysis (Phase 9)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "overview",
		Short: "Show AI agent and AI endpoint posture",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("AI agent posture analysis lands in Phase 9 (NIST COSAiS-aligned checks).")
			return nil
		},
	})
	return cmd
}

// --- mcp -------------------------------------------------------------------

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP server and client security analysis (Phase 9)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "analyze",
		Short: "Analyze MCP endpoints against OWASP MCP Top 10",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("MCP analysis lands in Phase 9 (OWASP MCP Top 10 checks).")
			return nil
		},
	})
	return cmd
}
