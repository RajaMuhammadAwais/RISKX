package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/RajaMuhammadAwais/RISKX/internal/core/config"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := dir + "/riskx"
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s: %v", out, err)
	}
	return bin
}

func TestCLIVersion(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %s: %v", out, err)
	}
	if !strings.Contains(string(out), "RISKX "+config.ToolVersion) {
		t.Fatalf("unexpected version output: %s", out)
	}
}

func TestCLIHelpExitCodes(t *testing.T) {
	bin := buildBinary(t)
	if out, err := exec.Command(bin, "--help").CombinedOutput(); err != nil {
		t.Fatalf("--help must exit 0: %s: %v", out, err)
	}
	// Unknown flag must exit 2 (execution/usage error), never 0 or 1.
	if out, err := exec.Command(bin, "--unknown-flag").CombinedOutput(); err == nil {
		t.Fatalf("unknown flag must fail: %s", out)
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2, got %d", exitErr.ExitCode())
		}
	}
}

func TestCLIDiscoverJSON(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "discover", "google.com").CombinedOutput()
	if err != nil {
		t.Fatalf("discover failed: %s: %v", out, err)
	}
	var r map[string]any
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("discover output must be canonical JSON: %v\noutput: %s", err, out)
	}
	payload, ok := r["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload in output: %s", out)
	}
	assets, ok := payload["assets"].([]any)
	if !ok || len(assets) == 0 {
		t.Fatalf("discover must return >=1 asset for google.com: %s", out)
	}
}

func TestCLIModeGatingActiveDenied(t *testing.T) {
	bin := buildBinary(t)
	// active validation without consent must exit 2 with a denial message.
	var out bytes.Buffer
	cmd := exec.Command(bin, "validate", "--mode", "validation", "f1")
	cmd.Stdin = strings.NewReader("no\n")
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		t.Fatal("unauthorized validation must fail")
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %v", err)
	}
}

func TestCLIModeGatingCIWithoutPreapprove(t *testing.T) {
	bin := buildBinary(t)
	var out bytes.Buffer
	cmd := exec.Command(bin, "validate", "--mode", "validation", "--ci", "f1")
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err == nil {
		t.Fatal("CI without --preapprove must fail for intrusive mode")
	}
	if !strings.Contains(out.String(), "--preapprove") {
		t.Fatalf("error must mention --preapprove; got: %s", out.String())
	}
}

func TestCLIDeltaMissingData(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "delta").CombinedOutput()
	if err == nil {
		t.Fatalf("delta without --data must fail: %s", out)
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %v", err)
	}
	if !strings.Contains(string(out), "no evidence store path") {
		t.Fatalf("expected no-evidence-store error, got: %s", out)
	}
}

// TestCLIDeltaTwoRuns uses a synthetic SQLite store (two stored snapshots,
// one asset changed between them) to pin the standalone `riskx delta`
// command's diff output end-to-end.
func TestCLIDeltaTwoRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic sqlite3 setup is POSIX-only in this harness")
	}
	bin := buildBinary(t)
	dir := t.TempDir()
	db := dir + "/riskx.db"

	// Build an empty store by running delta against --data (it opens the
	// store and tolerates "no snapshots yet" gracefully).
	if out, err := exec.Command(bin, "delta", "--data", db).CombinedOutput(); err != nil {
		t.Fatalf("store bootstrap failed: %s: %v", out, err)
	}

	if _, serr := exec.LookPath("sqlite3"); serr != nil {
		t.Skip("sqlite3 CLI unavailable")
	}

	// Seed two snapshots with a fingerprint drift using sqlite3.
	seeder := []string{
		`CREATE TABLE IF NOT EXISTS deltasnapshots (id TEXT PRIMARY KEY, taken_at TEXT NOT NULL, schema_version TEXT NOT NULL, payload TEXT NOT NULL);`,
		`INSERT INTO deltasnapshots VALUES ('snap-A','2026-01-01T00:00:00Z','delta-v1',
'{"id":"snap-A","taken_at":"2026-01-01T00:00:00Z","schema":"delta-v1","fingerprints":{},"asset_hashes":{},"finding_hashes":{},"assets":[{"id":"asset-x","kind":"domain","value":"a.example.com","host":"a.example.com","port":0,"protocol":"","exposure":"internet","criticality":"","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","provenance":{"source":"dns","method":"lookup","confidence":"high"},"fingerprint":{"http_server":"nginx/1.25"},"schema":"asset-v1"}],"findings":null}');`,
		`INSERT INTO deltasnapshots VALUES ('snap-B','2026-01-02T00:00:00Z','delta-v1',
'{"id":"snap-B","taken_at":"2026-01-02T00:00:00Z","schema":"delta-v1","fingerprints":{},"asset_hashes":{},"finding_hashes":{},"assets":[{"id":"asset-x","kind":"domain","value":"a.example.com","host":"a.example.com","port":0,"protocol":"","exposure":"internet","criticality":"","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-02T00:00:00Z","provenance":{"source":"dns","method":"lookup","confidence":"high"},"fingerprint":{"http_server":"nginx/1.27"},"schema":"asset-v1"}],"findings":null}');`,
	}
	for _, s := range seeder {
		if out, err := exec.Command("sqlite3", db, s).CombinedOutput(); err != nil {
			t.Fatalf("sqlite3 seed failed: %s: %v", out, err)
		}
	}

	deltaCmd := exec.Command(bin, "delta", "--data", db, "--since", "snap-A", "--json")
	var deltaOut bytes.Buffer
	deltaCmd.Stdout = &deltaOut
	deltaCmd.Stderr = os.Stderr
	if err := deltaCmd.Run(); err != nil {
		t.Fatalf("delta failed: %v", err)
	}
	var r map[string]any
	if err := json.Unmarshal(deltaOut.Bytes(), &r); err != nil {
		t.Fatalf("delta output must be canonical JSON: %v\noutput: %s", err, deltaOut.Bytes())
	}
	payload, ok := r["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload in output: %s", deltaOut.Bytes())
	}
	if payload["since"] != "snap-A" || payload["current"] != "snap-B" {
		t.Fatalf("expected since=snap-A current=snap-B, got %v", payload)
	}
	changes, ok := payload["changes"].([]any)
	if !ok {
		t.Fatalf("missing changes list in output: %s", deltaOut.Bytes())
	}
	if len(changes) != 1 {
		t.Fatalf("expected exactly one change (http_server drift), got %d: %s", len(changes), deltaOut.Bytes())
	}
	c := changes[0].(map[string]any)
	if c["kind"] != "changed_asset" {
		t.Fatalf("expected kind changed_asset, got %v", c["kind"])
	}
	if c["prior_run"] != "snap-A" || c["current_run"] != "snap-B" {
		t.Fatalf("run labels must match compared snapshots: %v", c)
	}
	changed, ok := c["changes"].([]any)
	if !ok || len(changed) != 1 || changed[0] != "http_server" {
		t.Fatalf("expected http_server change list, got %v", c["changes"])
	}
}
