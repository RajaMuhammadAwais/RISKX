package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIsSecure(t *testing.T) {
	cfg := Default()
	if cfg.Modes.Default != "passive" {
		t.Fatalf("default mode must be passive, got %q", cfg.Modes.Default)
	}
	if cfg.AI.Enabled {
		t.Fatal("AI must be disabled by default")
	}
	if cfg.Feeds.KEVStaleAfterDays != 1 {
		t.Fatalf("KEV staleness must be 1 day, got %d", cfg.Feeds.KEVStaleAfterDays)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("missing config must not error: %v", err)
	}
	if cfg.Modes.Default != "passive" {
		t.Fatal("missing config must yield secure defaults")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("unknown_field: value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("unknown fields must be rejected (fail secure)")
	}
}

func TestLoadRejectsBadMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("modes:\n  default: active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("invalid default mode must fail validation")
	}
}

func TestSavePermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "subdir", "config.yaml")
	if err := Save(p, Default()); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config must be written 0600, got %04o", info.Mode().Perm())
	}
}

func TestSaveRejectsTraversal(t *testing.T) {
	err := Save("../evil.yaml", Default())
	if err == nil {
		t.Fatal("path traversal must be rejected")
	}
}
