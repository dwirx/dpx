package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dwirx/dpx/internal/config"
)

func TestCreateDefault(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	if cfg.Version != 1 {
		t.Fatalf("version mismatch: got %d want 1", cfg.Version)
	}
	if cfg.DefaultSuffix != ".dpx" {
		t.Fatalf("suffix mismatch: got %q", cfg.DefaultSuffix)
	}
	if cfg.KeyFile != "~/.config/dpx/age-keys.txt" {
		t.Fatalf("key file mismatch: got %q", cfg.KeyFile)
	}
	if len(cfg.Discovery.Include) == 0 {
		t.Fatal("expected default discovery patterns")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, ".dpx.yaml")

	cfg := config.Default()
	cfg.Age.Recipients = []string{"age1example"}

	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Age.Recipients) != 1 || loaded.Age.Recipients[0] != "age1example" {
		t.Fatalf("recipients mismatch: %#v", loaded.Age.Recipients)
	}
}

func TestLoadParsesQuotedYamlValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, ".dpx.yaml")
	data := []byte(`
version: 1
default_suffix: ".secure.dpx"
key_file: "/tmp/dpx keys.txt"
age:
  recipients:
    - "age1quotedrecipient"
discovery:
  include:
    - ".env"
    - ".env.local"
`)

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.DefaultSuffix != ".secure.dpx" {
		t.Fatalf("default suffix mismatch: got %q", loaded.DefaultSuffix)
	}
	if loaded.KeyFile != "/tmp/dpx keys.txt" {
		t.Fatalf("key file mismatch: got %q", loaded.KeyFile)
	}
	if len(loaded.Age.Recipients) != 1 || loaded.Age.Recipients[0] != "age1quotedrecipient" {
		t.Fatalf("recipients mismatch: %#v", loaded.Age.Recipients)
	}
}
