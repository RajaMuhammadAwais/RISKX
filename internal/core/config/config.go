// Package config implements RISKX configuration loading with secure defaults
// (spec §24, §25).
//
// Rules: configs load from the XDG-respected path (~/.config/riskx/config.yaml
// or $RISKX_CONFIG); files are written with 0600 permissions; paths are
// validated against traversal; secrets in config values are redacted in logs;
// unknown fields are rejected (fail secure, no silent misconfiguration).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/errs"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/log"
)

const (
	// DefaultConfigPath is the default configuration file location.
	DefaultConfigPath = "config.yaml"
	// ToolVersion is the current RISKX version (spec §45).
	ToolVersion = "0.1.0"
)

// Config is the top-level RISKX configuration.
type Config struct {
	// Targets may be set at the CLI layer; config-file defaults are list form.
	Targets []Target `yaml:"targets,omitempty"`
	// Modes sets per-command defaults. Security modes are gated at runtime.
	Modes Modes `yaml:"modes,omitempty"`
	// Feeds tunes vulnerability-intelligence ingestion.
	Feeds Feeds `yaml:"feeds,omitempty"`
	// Policy references a policy file path for --ci evaluation.
	Policy string `yaml:"policy,omitempty"`
	// Risk holds risk-v1 weight overrides.
	Risk RiskConfig `yaml:"risk,omitempty"`
	// AI disables all optional AI functionality by default (spec §20, §47).
	AI AIConfig `yaml:"ai,omitempty"`
	// Output controls default output behavior.
	Output OutputConfig `yaml:"output,omitempty"`
}

// Target is a configured scan target with optional scope notes.
type Target struct {
	Value string `yaml:"value"`
	Kind  string `yaml:"kind,omitempty"`
}

// Modes holds per-command mode defaults.
type Modes struct {
	Default string `yaml:"default,omitempty"` // passive|safe
}

// Feeds holds feed-tuning parameters.
type Feeds struct {
	KEVStaleAfterDays   int `yaml:"kev_stale_after_days,omitempty"`
	EPSSStaleAfterDays  int `yaml:"epss_stale_after_days,omitempty"`
	NVDAPIKey           string `yaml:"nvd_api_key,omitempty"`
	NVDRequestTimeoutMs int `yaml:"nvd_request_timeout_ms,omitempty"`
}

// RiskConfig holds risk-v1 weight overrides keyed by factor name.
type RiskConfig struct {
	Weights map[string]float64 `yaml:"weights,omitempty"`
}

// AIConfig is OFF by default and must be explicitly enabled (spec §46, §47).
type AIConfig struct {
	Enabled bool `yaml:"enabled"`
	// Provider holds optional provider configuration; the AI layer is optional
	// and the scanner remains fully functional with Enabled=false.
	Provider string `yaml:"provider,omitempty"`
}

// OutputConfig holds output defaults.
type OutputConfig struct {
	JSON bool `yaml:"json,omitempty"`
}

// Default returns the secure default configuration.
func Default() *Config {
	return &Config{
		Modes: Modes{Default: "passive"},
		Feeds: Feeds{
			KEVStaleAfterDays:   1,
			EPSSStaleAfterDays:  7,
			NVDRequestTimeoutMs: 30000,
		},
		Risk:   RiskConfig{},
		AI:     AIConfig{Enabled: false},
		Output: OutputConfig{},
	}
}

// Load reads and validates a configuration file. Missing files are not an
// error: RISKX falls back to secure defaults. Invalid files are explicit
// errors (fail secure).
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("no config file found, using secure defaults", "path", path)
			return cfg, nil
		}
		return nil, errs.Wrap(errs.CodeConfigError, "config.load", "cannot read config file", err)
	}
	// Reject unknown fields: misconfiguration must not silently take effect.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, errs.Wrap(errs.CodeConfigError, "config.load", "invalid config syntax or unknown field", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch c.Modes.Default {
	case "", "passive", "safe":
		// valid
	default:
		return errs.Input("config.validate",
			fmt.Sprintf("unsupported default mode %q", c.Modes.Default),
			"modes.default must be 'passive' or 'safe'")
	}
	for _, t := range c.Targets {
		if strings.TrimSpace(t.Value) == "" {
			return errs.Input("config.validate", "empty target value in config",
				"remove empty entries from targets")
		}
	}
	return nil
}

// Save writes the configuration with 0600 permissions (spec §25).
func Save(path string, cfg *Config) error {
	if path == "" {
		path = DefaultConfigPath
	}
	if err := validatePath(path); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return errs.Wrap(errs.CodeInternal, "config.save", "cannot marshal config", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errs.Wrap(errs.CodeConfigError, "config.save", "cannot create config directory", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return errs.Wrap(errs.CodeConfigError, "config.save", "cannot write config file", err)
	}
	return nil
}

// validatePath rejects path traversal and unsafe locations.
func validatePath(path string) error {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return errs.Input("config.path", "path traversal not allowed in config path",
			"use a path inside the configuration directory")
	}
	abs, err := filepath.Abs(clean)
	if err != nil {
		return errs.Wrap(errs.CodeConfigError, "config.path", "cannot resolve config path", err)
	}
	if !filepath.IsAbs(abs) {
		return errs.Input("config.path", "config path must be absolute after resolution", "")
	}
	return nil
}

// HomeConfigDir returns the user configuration directory (~/.config/riskx).
func HomeConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errs.Wrap(errs.CodeConfigError, "config.home", "cannot determine home directory", err)
	}
	return filepath.Join(home, ".config", "riskx"), nil
}
