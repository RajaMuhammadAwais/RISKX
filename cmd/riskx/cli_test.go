package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
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
	if !strings.Contains(string(out), "RISKX 0.3.0") {
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
