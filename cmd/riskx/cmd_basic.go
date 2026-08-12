package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/buildinfo"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
)

// version prints the tool identity and model versions (spec §45).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print RISKX version and model versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Release builds inject buildinfo.Version via -ldflags; source
			// builds keep it empty and fall back to the in-source constant.
			// Empty fields print nothing — never "unknown" placeholders.
			ver := buildinfo.Version
			if ver == "" {
				ver = config.ToolVersion
			}
			fmt.Printf("RISKX %s\n", ver)
			if buildinfo.Commit != "" {
				fmt.Printf("commit: %s\n", buildinfo.Commit)
			}
			if buildinfo.BuildDate != "" {
				fmt.Printf("built: %s\n", buildinfo.BuildDate)
			}
			if buildinfo.Platform != "" {
				fmt.Printf("platform: %s\n", buildinfo.Platform)
			}
			fmt.Println("Risk model: risk-v1")
			// Deterministic ordering: map iteration order is random in Go.
			for _, s := range [3][2]string{{"asset", "asset-v1"}, {"finding", "finding-v1"}, {"evidence", "evidence-v1"}} {
				fmt.Printf("Schema %s: %s\n", s[0], s[1])
			}
			fmt.Println("Plugin API: plugin-v1")
			return nil
		},
	}
}

// init creates the user configuration directory and a default config.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize the RISKX configuration directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := config.HomeConfigDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				return fmt.Errorf("cannot create %s: %w", dir, err)
			}
			path := filepath.Join(dir, config.DefaultConfigPath)
			cfg := config.Default()
			if err := config.Save(path, cfg); err != nil {
				return err
			}
			fmt.Printf("Initialized RISKX configuration at %s (mode: passive by default)\n", path)
			fmt.Println("RISKX operates in PASSIVE mode unless a mode flag explicitly changes it.")
			return nil
		},
	}
}

// config manages the configuration file.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or validate the RISKX configuration",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			fmt.Printf("effective config: mode.default=%s ai.enabled=%v policy=%s\n",
				cfg.Modes.Default, cfg.AI.Enabled, cfg.Policy)
			fmt.Printf("feeds: kev_stale_days=%d epss_stale_days=%d nvd_timeout_ms=%d\n",
				cfg.Feeds.KEVStaleAfterDays, cfg.Feeds.EPSSStaleAfterDays, cfg.Feeds.NVDRequestTimeoutMs)
			return nil
		},
	})
	return cmd
}

// checkKEVReachable verifies outbound HTTPS reachability to the CISA KEV feed.
func checkKEVReachable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		"https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// doctor diagnoses the local environment (config readable, DB dir writable,
// network egress reachable for public feeds).
func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose the local RISKX environment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := true
			check := func(name string, err error) {
				if err != nil {
					fmt.Printf("FAIL  %s: %v\n", name, err)
					ok = false
				} else {
					fmt.Printf("OK    %s\n", name)
				}
			}
			_, loadErr := config.Load(flagConfig)
			check("config load", loadErr)
			dir, homeErr := config.HomeConfigDir()
			check("home config dir", homeErr)
			if homeErr == nil {
				check("config dir writable", os.MkdirAll(dir, 0700))
			}
			// Feed reachability: KEV is the canary (no auth required).
			check("feed reachability (KEV)", checkKEVReachable())
			if !ok {
				return fmt.Errorf("environment check failed; review FAIL entries above")
			}
			fmt.Println("environment OK")
			return nil
		},
	}
}
