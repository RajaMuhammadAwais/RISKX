// RISKX — enterprise cyber-risk assessment CLI.
//
// Safety defaults (spec §0, §7, §8):
//   - No mode ever exploits; VALIDATION requires explicit authorization.
//   - Config files written 0600; inputs validated; no shell construction.
//   - Exit codes: 0 no policy violation, 1 policy violation, 2 execution error.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/log"
)

var (
	flagConfig  string
	flagVerbose bool
	flagQuiet   bool
	flagJSON    bool
)

func main() {
	root := &cobra.Command{
		Use:   "riskx",
		Short: "RISKX — evidence-based cyber-risk assessment",
		Long: `RISKX is a CLI for continuous threat-exposure management: discover
assets, enrich vulnerability intelligence, score risk with an evidence-backed
deterministic model, rank attack paths, and report — all with mandatory evidence
attached to every finding.

Safety defaults: passive observation only; explicit authorization required for
active validation; every finding carries its evidence and source citations.

Exit codes: 0 = no policy violation, 1 = policy violation, 2 = execution error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       config.ToolVersion,
	}

	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to config file (default ~/.config/riskx/config.yaml)")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "enable debug logging")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress non-essential output")
	root.PersistentFlags().BoolVarP(&flagJSON, "json", "j", false, "emit canonical JSON output")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newInitCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newDiscoverCmd())
	root.AddCommand(newAssetsCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newVulnCmd())
	root.AddCommand(newRiskCmd())
	root.AddCommand(newGraphCmd())
	root.AddCommand(newAttackPathCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newExportCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newContinuousCmd())
	root.AddCommand(newCloudCmd())
	root.AddCommand(newIdentityCmd())
	root.AddCommand(newAgentCmd())
	root.AddCommand(newMCPCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newFeedCmd())
	root.AddCommand(newPrioritizeCmd())
	root.AddCommand(newDeltaCmd())
	root.AddCommand(newExplainCmd())

	configureLogging()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func configureLogging() {
	level := log.LevelInfo
	if flagQuiet {
		level = log.LevelQuiet
	} else if flagVerbose {
		level = log.LevelDebug
	}
	log.SetLevel(level)
	log.SetJSON(flagJSON)
}
