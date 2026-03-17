package safeio_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dwirx/dpx/internal/safeio"
)

func TestReadFileReadsExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	want := []byte("hello\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := safeio.ReadFile(path)
	if err != nil {
		t.Fatalf("safe read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read mismatch: got %q want %q", got, want)
	}
}

func TestWriteFileRejectsSymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is platform-specific on windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "out.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	err := safeio.WriteFile(link, []byte("NEW"), 0o600)
	if err == nil {
		t.Fatal("expected symlink write to fail")
	}
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("target should still exist: %v", statErr)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(data) != "ORIGINAL" {
		t.Fatalf("target modified unexpectedly: %q", data)
	}
}

func TestStatReturnsNotExist(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.txt")
	_, err := safeio.Stat(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not exist, got %v", err)
	}
}
