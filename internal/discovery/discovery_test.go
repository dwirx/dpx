package discovery_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dwirx/dpx/internal/discovery"
)

func TestFindCandidatesRanksExpectedEnvFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, ".env"))
	mustWriteFile(t, filepath.Join(dir, ".env.local"))
	mustWriteFile(t, filepath.Join(dir, "notes.txt"))
	mustWriteFile(t, filepath.Join(dir, ".env.dpx"))

	candidates, err := discovery.FindCandidates(dir)
	if err != nil {
		t.Fatalf("find candidates: %v", err)
	}
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}
	if filepath.Base(candidates[0].Path) != ".env" {
		t.Fatalf("expected .env to rank first, got %q", filepath.Base(candidates[0].Path))
	}
	for _, candidate := range candidates {
		if filepath.Base(candidate.Path) == ".env.dpx" {
			t.Fatalf("encrypted files should not be suggested by default")
		}
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
