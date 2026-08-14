package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileConfigRepositoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	repo := FileConfigRepository{Path: path}
	cfg := newConfig()
	cfg.DefaultTargetIPv4 = "10.0.0.8"
	cfg.ManagedRules = append(cfg.ManagedRules, ManagedRule{
		ID: "rule1", Description: "SSH", ListenAddress: "0.0.0.0", ListenPort: 71,
		ConnectAddress: "10.0.0.8", ConnectPort: 22, FirewallName: "ServerPortForward-rule1",
	})
	if err := repo.Save(cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DefaultTargetIPv4 != cfg.DefaultTargetIPv4 || len(loaded.ManagedRules) != 1 {
		t.Fatalf("unexpected loaded config: %#v", loaded)
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".config-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func TestFileConfigRepositoryRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"managedRules":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileConfigRepository{Path: path}).Load(); err == nil {
		t.Fatal("expected unknown config field to fail")
	}
}
