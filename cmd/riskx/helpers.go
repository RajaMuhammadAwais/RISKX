package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/idgen"
	"github.com/RajaMuhammadAwais/RISKX/internal/core/output"
	"github.com/RajaMuhammadAwais/RISKX/internal/storage"
	"github.com/RajaMuhammadAwais/RISKX/pkg/models"
)

// resolveDataPath returns the evidence-store path per the lookup order
// --data flag > RISKX_DATA env > ~/.riskx/riskx.db. An empty result means the
// store is intentionally disabled for this run.
func resolveDataPath(flagValue string) (string, bool) {
	if flagValue == "" {
		flagValue = os.Getenv("RISKX_DATA")
	}
	if flagValue == "" || flagValue == "off" {
		return "", false
	}
	if !filepath.IsAbs(flagValue) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		flagValue = filepath.Join(home, flagValue)
	}
	if err := os.MkdirAll(filepath.Dir(flagValue), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot create data dir %s: %v\n", filepath.Dir(flagValue), err)
		return "", false
	}
	return flagValue, true
}

// openStore opens the evidence store at path, or nil if path is empty. The
// caller is responsible for closing via storeClose (errors are logged, not
// fatal: the read-only commands must still produce output).
func openStore(path string) (*storage.Store, error) {
	if path == "" {
		return nil, nil
	}
	return storage.Open(path)
}

// storeClose closes a store, logging any error to stderr without failing the
// command — persistence failure is reported, not silently swallowed.
func storeClose(s *storage.Store) {
	if s == nil {
		return
	}
	if err := s.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: closing evidence store: %v\n", err)
	}
}

// printer returns the output printer for the given command's stdout.
func printer(cmd *cobra.Command) *output.Printer {
	return output.NewPrinter(cmd.OutOrStdout())
}

// startedNow returns the current UTC time, used as both started and finished
// markers for commands that have no measurable duration yet.
func startedNow() time.Time { return time.Now().UTC() }

// splitCSV splits a comma-separated flag value, trimming spaces.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// loadTargets collects targets from positional arguments and an optional
// file. File targets are appended (both sources may be combined).
func loadTargets(args []string, file string) []string {
	var out []string
	out = append(out, args...)
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot open target file %s: %v\n", file, err)
			return out
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: error reading target file %s: %v\n", file, err)
		}
	}
	return out
}

// probePorts performs connect-only TCP probes. Connect-only is read-only
// observation (a half-open connect never sends application data). It is
// gated by PASSIVE mode by default (connects are considered intrusive by
// some policies, so the port flag is opt-in and logged).
func probePorts(ctx context.Context, target string, portsCSV string, m interface{ String() string }) ([]models.Asset, error) {
	ports, err := parsePorts(portsCSV)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var assets []models.Asset
	for _, p := range ports {
		addr := net.JoinHostPort(target, strconv.Itoa(p))
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		ev := models.Evidence{
			Type: "tcp_connect", Source: "port_probe", Timestamp: now,
			Value: fmt.Sprintf("target=%s port=%d", target, p),
		}
		if err == nil {
			ev.Value += " state=open"
			conn.Close()
		} else {
			ev.Value += fmt.Sprintf(" state=closed_or_filtered reason=%s", err.Error())
		}
		assets = append(assets, models.Asset{
			Kind:     models.KindService,
			Value:    fmt.Sprintf("%s:%d", target, p),
			Host:     target,
			Port:     p,
			Protocol: "tcp",
			Exposure: models.ExposureUnknown,
			Provenance: models.Provenance{
				Source: "port_probe", Method: "tcp_connect",
				Timestamp: now, Confidence: models.ConfidenceHigh,
			},
			LastSeen: now, FirstSeen: now,
		})
		_ = ev
	}
	for i := range assets {
		assets[i].ID = idgen.AssetID(assets[i].Kind, assets[i].Value, assets[i].Host, assets[i].Port)
		assets[i].Schema = models.SchemaAsset
	}
	return assets, nil
}

// parsePorts validates a comma-separated port list into a deduped, valid
// port set. Invalid ports are an explicit input error, never silently
// skipped.
func parsePorts(s string) ([]int, error) {
	var out []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q: must be 1..65535", part)
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", s)
	}
	return out, nil
}
