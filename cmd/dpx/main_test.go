package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInitCreatesConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stdout := new(bytes.Buffer)

	if err := run([]string{"init"}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run init: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".dpx.yaml")); err != nil {
		t.Fatalf("expected .dpx.yaml: %v", err)
	}
}

func TestRunVersionCommandPrintsVersion(t *testing.T) {
	stdout := new(bytes.Buffer)
	oldVersion := version
	version = "v1.2.3-test"
	t.Cleanup(func() {
		version = oldVersion
	})

	if err := run([]string{"version"}, runOptions{cwd: t.TempDir(), stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run version: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "v1.2.3-test") {
		t.Fatalf("expected version output, got %q", got)
	}
}

func TestRunVersionFlagPrintsVersion(t *testing.T) {
	stdout := new(bytes.Buffer)
	oldVersion := version
	version = "v9.9.9-test"
	t.Cleanup(func() {
		version = oldVersion
	})

	if err := run([]string{"--version"}, runOptions{cwd: t.TempDir(), stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run --version: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "v9.9.9-test") {
		t.Fatalf("expected version output, got %q", got)
	}
}

func TestRunHelpListsVersionCommand(t *testing.T) {
	t.Parallel()

	stdout := new(bytes.Buffer)
	if err := run([]string{"help"}, runOptions{cwd: t.TempDir(), stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run help: %v", err)
	}

	if got := stdout.String(); !strings.Contains(got, "version") {
		t.Fatalf("expected help to mention version command, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "doctor") {
		t.Fatalf("expected help to mention doctor command, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "dpx <command> [flags]") {
		t.Fatalf("expected dpx branding in help, got %q", got)
	}
}

func TestRunDoctorReportsHealthyProject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "` + filepath.Join(dir, "keys.txt") + `"
age:
  recipients:
    - "age1testrecipient"
discovery:
  include:
    - ".env"
`
	if err := os.WriteFile(filepath.Join(dir, ".dpx.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.txt"), []byte("AGE-SECRET-KEY-TEST\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"doctor"}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run doctor: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "DPX Doctor") {
		t.Fatalf("expected doctor title, got %q", got)
	}
	if !strings.Contains(got, ".dpx.yaml") {
		t.Fatalf("expected primary config path in output, got %q", got)
	}
	if !strings.Contains(got, "Recipients: 1") {
		t.Fatalf("expected recipient count in output, got %q", got)
	}
	if !strings.Contains(got, "Suggested Files: 1") {
		t.Fatalf("expected suggested file count in output, got %q", got)
	}
}

func TestRunDoctorFallsBackToLegacyConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "` + filepath.Join(dir, "legacy-keys.txt") + `"
age:
  recipients:
    - "age1legacyrecipient"
discovery:
  include:
    - ".env"
`
	if err := os.WriteFile(filepath.Join(dir, ".dopx.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"doctor"}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run doctor: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, ".dopx.yaml") || !strings.Contains(strings.ToLower(got), "legacy") {
		t.Fatalf("expected legacy config notice, got %q", got)
	}
}

func TestRunKeygenWritesIdentityFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-keys.txt")
	stdout := new(bytes.Buffer)

	if err := run([]string{"keygen", "--out", keyPath}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run keygen: %v", err)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !strings.Contains(string(data), "AGE-SECRET-KEY-") {
		t.Fatalf("expected age secret key, got %q", string(data))
	}
}

func TestRunPasswordEncryptDecryptCommands(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\nHELLO=world\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"encrypt", sourcePath, "--password", "secret-123"}, runOptions{cwd: dir, stdout: new(bytes.Buffer), stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run encrypt: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	encryptedPath := sourcePath + ".dpx"
	if err := run([]string{"decrypt", encryptedPath, "--password", "secret-123"}, runOptions{cwd: dir, stdout: new(bytes.Buffer), stderr: new(bytes.Buffer), stdin: strings.NewReader("")}); err != nil {
		t.Fatalf("run decrypt: %v", err)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestPromptSecretFallsBackWithoutTTY(t *testing.T) {
	t.Parallel()

	stdout := new(bytes.Buffer)
	secret, err := promptSecret(runOptions{stdin: strings.NewReader("secret-123\n"), stdout: stdout, stderr: new(bytes.Buffer), cwd: t.TempDir()}, "Password: ")
	if err != nil {
		t.Fatalf("prompt secret: %v", err)
	}
	if secret != "secret-123" {
		t.Fatalf("secret mismatch: got %q", secret)
	}
	if !strings.Contains(stdout.String(), "Password: ") {
		t.Fatalf("expected password label in output, got %q", stdout.String())
	}
}

func TestRunTUIEncryptsSuggestedFileWithFullscreenShell(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	input := strings.NewReader("1\n1\n2\nsecret-123\n\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: input}); err != nil {
		t.Fatalf("run tui: %v", err)
	}

	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output: %v", err)
	}
	if !strings.Contains(stdout.String(), "DPX TUI") {
		t.Fatalf("expected branded fullscreen tui output, got %q", stdout.String())
	}
}
