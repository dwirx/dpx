package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/envelope"
	"github.com/dwirx/dpx/internal/selfupdate"
)

func TestDPXHelperPrintEnv(t *testing.T) {
	if os.Getenv("DPX_HELPER_PRINT_ENV") != "1" {
		return
	}
	key := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			key = os.Args[i+1]
			break
		}
	}
	if key == "" {
		os.Exit(2)
	}
	fmt.Fprint(os.Stdout, os.Getenv(key))
	os.Exit(0)
}

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
	if got := stdout.String(); !strings.Contains(got, "uninstall") {
		t.Fatalf("expected help to mention uninstall command, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "update") {
		t.Fatalf("expected help to mention update command, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "rollback") {
		t.Fatalf("expected help to mention rollback command, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "dpx uninstall --yes --remove-key --remove-encrypted") {
		t.Fatalf("expected help to include uninstall usage example, got %q", got)
	}
	if got := stdout.String(); !strings.Contains(got, "dpx <command> [flags]") {
		t.Fatalf("expected dpx branding in help, got %q", got)
	}
}

func TestRunUpdateCommandUsesUpdater(t *testing.T) {
	oldUpdate := runSelfUpdate
	t.Cleanup(func() {
		runSelfUpdate = oldUpdate
	})

	called := false
	runSelfUpdate = func(opts selfupdate.UpdateOptions) (selfupdate.Result, error) {
		called = true
		if opts.Version != "v1.2.3" {
			t.Fatalf("expected version v1.2.3, got %q", opts.Version)
		}
		return selfupdate.Result{
			CurrentPath: "/tmp/dpx",
			BackupPath:  "/tmp/dpx.rollback",
			Version:     "v1.2.3",
		}, nil
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"update", "--version", "v1.2.3"}, runOptions{
		cwd:    t.TempDir(),
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run update: %v", err)
	}
	if !called {
		t.Fatal("expected updater to be called")
	}
	if !strings.Contains(stdout.String(), "Updated dpx (v1.2.3)") {
		t.Fatalf("expected update success output, got %q", stdout.String())
	}
}

func TestRunRollbackCommandUsesRollbacker(t *testing.T) {
	oldRollback := runSelfRollback
	t.Cleanup(func() {
		runSelfRollback = oldRollback
	})

	called := false
	runSelfRollback = func(opts selfupdate.RollbackOptions) (selfupdate.Result, error) {
		called = true
		return selfupdate.Result{
			CurrentPath: "/tmp/dpx",
			BackupPath:  "/tmp/dpx.rollback",
		}, nil
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"rollback"}, runOptions{
		cwd:    t.TempDir(),
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run rollback: %v", err)
	}
	if !called {
		t.Fatal("expected rollbacker to be called")
	}
	if !strings.Contains(stdout.String(), "Rollback completed.") {
		t.Fatalf("expected rollback success output, got %q", stdout.String())
	}
}

func TestRunRollbackRejectsUnexpectedArg(t *testing.T) {
	err := run([]string{"rollback", "extra"}, runOptions{
		cwd:    t.TempDir(),
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatal("expected rollback arg validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unexpected argument") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunUninstallRemovesConfigKeyAndEncryptedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-keys.txt")
	cfg := config.Default()
	cfg.KeyFile = keyPath
	if err := config.Save(filepath.Join(dir, ".dpx.yaml"), cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-TEST\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.dpx"), []byte("encrypted"), 0o600); err != nil {
		t.Fatalf("write encrypted: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"uninstall", "--yes", "--remove-key", "--remove-encrypted"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run uninstall: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".dpx.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected config removed, stat err=%v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected key removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.dpx")); !os.IsNotExist(err) {
		t.Fatalf("expected encrypted file removed, stat err=%v", err)
	}
	if !strings.Contains(stdout.String(), "Uninstall completed") {
		t.Fatalf("expected uninstall success message, got %q", stdout.String())
	}
}

func TestRunUninstallCancelsWithoutConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Default()
	cfg.KeyFile = filepath.Join(dir, "age-keys.txt")
	if err := config.Save(filepath.Join(dir, ".dpx.yaml"), cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"uninstall"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader("no\n"),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatalf("expected uninstall cancel error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "canceled") {
		t.Fatalf("expected canceled error, got %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(dir, ".dpx.yaml")); statErr != nil {
		t.Fatalf("expected config to remain after cancel, stat err=%v", statErr)
	}
}

func TestRunUninstallRejectsUnsafeCustomKeyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsideKey := filepath.Join(outsideDir, "outside-age-keys.txt")
	if err := os.WriteFile(outsideKey, []byte("AGE-SECRET-KEY-TEST\n"), 0o600); err != nil {
		t.Fatalf("write outside key: %v", err)
	}

	cfg := config.Default()
	cfg.KeyFile = outsideKey
	if err := config.Save(filepath.Join(dir, ".dpx.yaml"), cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"uninstall", "--yes", "--remove-key"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatalf("expected unsafe key path error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refusing to remove key file") {
		t.Fatalf("expected safety error, got %v", err)
	}

	if _, statErr := os.Stat(outsideKey); statErr != nil {
		t.Fatalf("expected outside key to remain, stat err=%v", statErr)
	}
}

func TestRunUninstallDoesNotPartiallyRemoveWhenKeyPathIsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keysdir")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}

	cfg := config.Default()
	cfg.KeyFile = keyDir
	cfgPath := filepath.Join(dir, ".dpx.yaml")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"uninstall", "--yes", "--remove-key"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatalf("expected error for directory key path")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "directory") {
		t.Fatalf("expected directory error, got %v", err)
	}

	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("expected config to remain on preflight failure, stat err=%v", statErr)
	}
}

func TestRunDoctorReportsHealthyProject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.ToSlash(filepath.Join(dir, "keys.txt"))
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "` + keyPath + `"
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
	legacyKeyPath := filepath.ToSlash(filepath.Join(dir, "legacy-keys.txt"))
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "` + legacyKeyPath + `"
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

	cfgPath := filepath.Join(dir, ".dpx.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load .dpx.yaml: %v", err)
	}
	if cfg.KeyFile != keyPath {
		t.Fatalf("expected key_file=%q, got %q", keyPath, cfg.KeyFile)
	}
	if len(cfg.Age.Recipients) == 0 {
		t.Fatalf("expected recipient to be added into config")
	}
	if !strings.HasPrefix(cfg.Age.Recipients[len(cfg.Age.Recipients)-1], "age1") {
		t.Fatalf("expected age recipient, got %q", cfg.Age.Recipients[len(cfg.Age.Recipients)-1])
	}
}

func TestRunKeygenAppendsRecipientToExistingConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".dpx.yaml")
	initial := `version: 1
default_suffix: ".dpx"
key_file: "~/.config/dpx/age-keys.txt"
age:
  recipients:
    - "age1existingrecipientxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	keyPath := filepath.Join(dir, "age-keys.txt")
	if err := run([]string{"keygen", "--out", keyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run keygen: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.KeyFile != keyPath {
		t.Fatalf("expected key_file=%q, got %q", keyPath, cfg.KeyFile)
	}
	if len(cfg.Age.Recipients) < 2 {
		t.Fatalf("expected recipient to be appended, got %#v", cfg.Age.Recipients)
	}
	if cfg.Age.Recipients[0] != "age1existingrecipientxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		t.Fatalf("expected existing recipient preserved, got %#v", cfg.Age.Recipients)
	}
	if !strings.HasPrefix(cfg.Age.Recipients[len(cfg.Age.Recipients)-1], "age1") {
		t.Fatalf("expected generated age recipient, got %q", cfg.Age.Recipients[len(cfg.Age.Recipients)-1])
	}
}

func TestRunKeygenUsesExistingKeyByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-keys.txt")

	if err := run([]string{"keygen", "--out", keyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("initial keygen: %v", err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read initial key file: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"keygen", "--out", keyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("second keygen: %v", err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read second key file: %v", err)
	}

	if !bytes.Equal(before, after) {
		t.Fatalf("expected existing key to be reused")
	}
	if !strings.Contains(stdout.String(), "using existing") {
		t.Fatalf("expected status to mention existing key, got %q", stdout.String())
	}

	cfg, err := config.Load(filepath.Join(dir, ".dpx.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Age.Recipients) != 1 {
		t.Fatalf("expected single recipient after reusing key, got %#v", cfg.Age.Recipients)
	}
}

func TestRunKeygenRegeneratesWhenRequested(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-keys.txt")

	if err := run([]string{"keygen", "--out", keyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("initial keygen: %v", err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read initial key file: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"keygen", "--out", keyPath, "--regen"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("regen keygen: %v", err)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read regenerated key file: %v", err)
	}

	if bytes.Equal(before, after) {
		t.Fatalf("expected key file to change after --regen")
	}
	if !strings.Contains(stdout.String(), "regenerated") {
		t.Fatalf("expected status to mention regenerated key, got %q", stdout.String())
	}

	cfg, err := config.Load(filepath.Join(dir, ".dpx.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Age.Recipients) < 2 {
		t.Fatalf("expected old and new recipients to be tracked, got %#v", cfg.Age.Recipients)
	}
}

func TestRunKeygenImportsFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	importRaw := strings.Join([]string{
		"# created: 2026-03-17T11:47:02Z",
		"# public key: " + identity.PublicKey,
		identity.PrivateKey,
		"",
	}, "\n")

	importPath := filepath.Join(dir, "source-age-keys.txt")
	if err := os.WriteFile(importPath, []byte(importRaw), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	outPath := filepath.Join(dir, "age-keys.txt")
	stdout := new(bytes.Buffer)
	if err := run([]string{"keygen", "--out", outPath, "--import-file", importPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run keygen import-file: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out key file: %v", err)
	}
	if !strings.Contains(string(data), identity.PrivateKey) || !strings.Contains(string(data), identity.PublicKey) {
		t.Fatalf("expected imported identity in output key file, got %q", string(data))
	}
	if !strings.Contains(stdout.String(), "imported") {
		t.Fatalf("expected imported status, got %q", stdout.String())
	}

	cfg, err := config.Load(filepath.Join(dir, ".dpx.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !containsString(cfg.Age.Recipients, identity.PublicKey) {
		t.Fatalf("expected imported public key in recipients, got %#v", cfg.Age.Recipients)
	}
}

func TestRunKeygenImportFileUsesImportPathWhenOutNotProvided(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	importRaw := strings.Join([]string{
		"# created: 2026-03-17T11:47:02Z",
		"# public key: " + identity.PublicKey,
		identity.PrivateKey,
		"",
	}, "\n")
	importPath := filepath.Join(dir, "age-keys.txt")
	if err := os.WriteFile(importPath, []byte(importRaw), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"keygen", "--import-file", importPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run keygen import-file without out: %v", err)
	}

	cfg, err := config.Load(filepath.Join(dir, ".dpx.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.KeyFile != importPath {
		t.Fatalf("expected key_file to use import path %q, got %q", importPath, cfg.KeyFile)
	}
	if !containsString(cfg.Age.Recipients, identity.PublicKey) {
		t.Fatalf("expected imported public key in recipients, got %#v", cfg.Age.Recipients)
	}
	if !strings.Contains(stdout.String(), "Status: imported") {
		t.Fatalf("expected imported status output, got %q", stdout.String())
	}
}

func TestRunKeygenImportsFromStdin(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	importRaw := strings.Join([]string{
		"# created: 2026-03-17T11:47:02Z",
		"# public key: " + identity.PublicKey,
		identity.PrivateKey,
		"",
	}, "\n")

	outPath := filepath.Join(dir, "age-keys.txt")
	stdout := new(bytes.Buffer)
	if err := run([]string{"keygen", "--out", outPath, "--import-stdin"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(importRaw),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run keygen import-stdin: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out key file: %v", err)
	}
	if !strings.Contains(string(data), identity.PrivateKey) || !strings.Contains(string(data), identity.PublicKey) {
		t.Fatalf("expected imported identity in output key file, got %q", string(data))
	}
	if !strings.Contains(stdout.String(), "imported") {
		t.Fatalf("expected imported status, got %q", stdout.String())
	}
}

func TestRunTUIImportsKeyFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	importRaw := strings.Join([]string{
		"# created: 2026-03-17T11:47:02Z",
		"# public key: " + identity.PublicKey,
		identity.PrivateKey,
		"",
	}, "\n")
	importPath := filepath.Join(dir, "source-age-keys.txt")
	if err := os.WriteFile(importPath, []byte(importRaw), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}
	outPath := filepath.Join(dir, "imported-age-keys.txt")

	input := strings.NewReader("5\n1\n" + importPath + "\n" + outPath + "\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{
		cwd:    dir,
		stdin:  input,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run tui import: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read imported key file: %v", err)
	}
	if !strings.Contains(string(data), identity.PrivateKey) {
		t.Fatalf("expected imported private key in output file")
	}
	if !strings.Contains(stdout.String(), "Imported key ->") {
		t.Fatalf("expected import output message, got %q", stdout.String())
	}

	cfg, err := config.Load(filepath.Join(dir, ".dpx.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !containsString(cfg.Age.Recipients, identity.PublicKey) {
		t.Fatalf("expected imported public key in config recipients, got %#v", cfg.Age.Recipients)
	}
}

func TestRunTUIDoctorAction(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.ToSlash(filepath.Join(dir, "keys.txt"))
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "` + keyPath + `"
age:
  recipients:
    - "age1testrecipient"
`
	if err := os.WriteFile(filepath.Join(dir, ".dpx.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.txt"), []byte("AGE-SECRET-KEY-TEST\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	input := strings.NewReader("6\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{
		cwd:    dir,
		stdin:  input,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run tui doctor: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "DPX Doctor") {
		t.Fatalf("expected doctor output in tui, got %q", got)
	}
	if !strings.Contains(got, "Recipients: 1") {
		t.Fatalf("expected recipient count in doctor output, got %q", got)
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

func TestRunEncryptAcceptsKDFProfileFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"encrypt", sourcePath, "--password", "secret-123", "--kdf-profile", "hardened"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt with kdf profile: %v", err)
	}

	data, err := os.ReadFile(sourcePath + ".dpx")
	if err != nil {
		t.Fatalf("read encrypted output: %v", err)
	}
	meta, _, err := envelope.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal encrypted output: %v", err)
	}
	if meta.KDF == nil {
		t.Fatal("expected kdf metadata")
	}
	if meta.KDF.MemoryKiB != 128*1024 {
		t.Fatalf("expected hardened profile memory, got %d", meta.KDF.MemoryKiB)
	}
}

func TestRunEncryptRejectsUnknownKDFProfileFlag(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := run([]string{"encrypt", sourcePath, "--password", "secret-123", "--kdf-profile", "unknown"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatal("expected unknown kdf profile to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "kdf profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunEncDecAliases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\nHELLO=world\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"enc", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run enc alias: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	encryptedPath := sourcePath + ".dpx"
	if err := run([]string{"dec", encryptedPath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run dec alias: %v", err)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunAutoPrefixCommandResolvesEncryptDecrypt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\nHELLO=world\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"encr", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encr prefix: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	if err := run([]string{"decr", sourcePath + ".dpx", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run decr prefix: %v", err)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunSingleLetterAliasesEncryptDecrypt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\nHELLO=world\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"e", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run e alias: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	if err := run([]string{"d", sourcePath + ".dpx", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run d alias: %v", err)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunUnknownCommandHasSuggestion(t *testing.T) {
	t.Parallel()

	err := run([]string{"decpyt"}, runOptions{
		cwd:    t.TempDir(),
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatalf("expected unknown command error")
	}
	if !strings.Contains(err.Error(), "did you mean") || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("expected suggestion for decrypt, got %v", err)
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

	input := strings.NewReader("1\n1\n2\nsecret-123\nsecret-123\n\n")
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

func TestRunTUIEncryptsManualPathWhenNoSuggestions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	input := strings.NewReader("1\n1\n" + sourcePath + "\n2\nsecret-123\nsecret-123\n\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{cwd: dir, stdout: stdout, stderr: new(bytes.Buffer), stdin: input}); err != nil {
		t.Fatalf("run tui: %v", err)
	}

	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output: %v", err)
	}
	if !strings.Contains(stdout.String(), "File to encrypt") {
		t.Fatalf("expected manual file prompt, got %q", stdout.String())
	}
}

func TestRunEncryptAllowsManualPathWhenSuggestionsExist(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	suggestedPath := filepath.Join(dir, ".env")
	manualPath := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(suggestedPath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write suggested file: %v", err)
	}
	if err := os.WriteFile(manualPath, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write manual file: %v", err)
	}

	stdin := strings.NewReader("3\n" + manualPath + "\nsecret-123\nsecret-123\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"encrypt"}, runOptions{
		cwd:    dir,
		stdin:  stdin,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt without file path: %v", err)
	}

	if _, err := os.Stat(manualPath + ".dpx"); err != nil {
		t.Fatalf("expected manual path to be encrypted: %v", err)
	}
	if !strings.Contains(stdout.String(), "File to encrypt") {
		t.Fatalf("expected manual path prompt, got %q", stdout.String())
	}
}

func TestRunEncryptPromptsManualPathWhenNoSuggestions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manualPath := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(manualPath, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write manual file: %v", err)
	}

	stdin := strings.NewReader("1\n" + manualPath + "\nsecret-123\nsecret-123\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"encrypt"}, runOptions{
		cwd:    dir,
		stdin:  stdin,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt without suggestions: %v", err)
	}

	if _, err := os.Stat(manualPath + ".dpx"); err != nil {
		t.Fatalf("expected manual path to be encrypted: %v", err)
	}
	if !strings.Contains(stdout.String(), "File to encrypt") {
		t.Fatalf("expected manual path prompt, got %q", stdout.String())
	}
}

func TestRunEncryptSuggestionsIncludeCommonFileTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	files := []string{".env", "notes.txt", "README.md", "script.js", "payload.bin", "app.exe"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	stdin := strings.NewReader("1\nsecret-123\nsecret-123\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"encrypt"}, runOptions{
		cwd:    dir,
		stdin:  stdin,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt with suggestions: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Select a file to encrypt (all files mode)") {
		t.Fatalf("expected updated suggestion title, got %q", out)
	}
	for _, name := range files {
		if !strings.Contains(out, name) {
			t.Fatalf("expected %s in suggestion output, got %q", name, out)
		}
	}
}

func TestRunEncryptCanSearchCandidateByKeyword(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	notesPath := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(envPath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.WriteFile(notesPath, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write notes: %v", err)
	}

	stdin := strings.NewReader("4\nnotes\nsecret-123\nsecret-123\n")
	if err := run([]string{"encrypt"}, runOptions{
		cwd:    dir,
		stdin:  stdin,
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt search flow: %v", err)
	}

	if _, err := os.Stat(notesPath + ".dpx"); err != nil {
		t.Fatalf("expected searched file to be encrypted: %v", err)
	}
}

func TestRunEncryptCanSwitchToEnvMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	notesPath := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(envPath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if err := os.WriteFile(notesPath, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write notes: %v", err)
	}

	stdin := strings.NewReader("5\n1\nsecret-123\nsecret-123\n")
	if err := run([]string{"encrypt"}, runOptions{
		cwd:    dir,
		stdin:  stdin,
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt switch scope flow: %v", err)
	}

	if _, err := os.Stat(envPath + ".dpx"); err != nil {
		t.Fatalf("expected .env to be encrypted after switching mode: %v", err)
	}
	if _, err := os.Stat(notesPath + ".dpx"); err == nil {
		t.Fatalf("did not expect notes.txt to be encrypted in this flow")
	}
}

func TestRunDirectFileEncryptsUsingPassword(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("TOKEN=abc\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run direct encrypt: %v", err)
	}

	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output: %v", err)
	}
}

func TestRunDirectDpxDecryptsUsingPassword(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("TOKEN=abc\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"encrypt", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	encryptedPath := sourcePath + ".dpx"
	if err := run([]string{encryptedPath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run direct decrypt: %v", err)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunPasswordEncryptDecryptSupportsVariousFileTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{name: "notes.txt", data: []byte("hello text file\n"), mode: 0o600},
		{name: "README.md", data: []byte("# Title\n\nmarkdown content\n"), mode: 0o600},
		{name: "app.exe", data: []byte{0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, mode: 0o755},
		{name: "payload.bin", data: []byte{0x00, 0x01, 0x7f, 0xff, 0x10, 0x20, 0x30, 0x40}, mode: 0o600},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sourcePath := filepath.Join(dir, tc.name)
			if err := os.WriteFile(sourcePath, tc.data, tc.mode); err != nil {
				t.Fatalf("write source: %v", err)
			}

			if err := run([]string{"encrypt", sourcePath, "--password", "secret-123"}, runOptions{
				cwd:    dir,
				stdin:  strings.NewReader(""),
				stdout: new(bytes.Buffer),
				stderr: new(bytes.Buffer),
			}); err != nil {
				t.Fatalf("encrypt %s: %v", tc.name, err)
			}
			if err := os.Remove(sourcePath); err != nil {
				t.Fatalf("remove source: %v", err)
			}

			encryptedPath := sourcePath + ".dpx"
			if err := run([]string{"decrypt", encryptedPath, "--password", "secret-123"}, runOptions{
				cwd:    dir,
				stdin:  strings.NewReader(""),
				stdout: new(bytes.Buffer),
				stderr: new(bytes.Buffer),
			}); err != nil {
				t.Fatalf("decrypt %s: %v", tc.name, err)
			}

			restored, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatalf("read restored: %v", err)
			}
			if !bytes.Equal(restored, tc.data) {
				t.Fatalf("restored content mismatch for %s", tc.name)
			}

			info, err := os.Stat(sourcePath)
			if err != nil {
				t.Fatalf("stat restored: %v", err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != tc.mode.Perm() {
				t.Fatalf("mode mismatch for %s: got %04o want %04o", tc.name, info.Mode().Perm(), tc.mode.Perm())
			}
		})
	}
}

func TestExpandHomeSupportsSlashAndBackslash(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("user home dir: %v", err)
	}

	tests := []string{"~/dpx/keys.txt", "~\\dpx\\keys.txt"}
	for _, input := range tests {
		got := expandHome(input)
		if !strings.HasPrefix(got, home) {
			t.Fatalf("expandHome(%q) should start with home dir %q, got %q", input, home, got)
		}
		if !strings.Contains(got, "dpx") || !strings.Contains(got, "keys.txt") {
			t.Fatalf("expandHome(%q) unexpected result %q", input, got)
		}
	}
}

func TestRunDirectEnvPrefersPasswordEvenWhenRecipientsConfigured(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "~/.config/dpx/age-keys.txt"
age:
  recipients:
    - "age1invalidrecipientthatwouldfailifused"
`
	if err := os.WriteFile(filepath.Join(dir, ".dpx.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("TOKEN=abc\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{sourcePath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader("secret-123\nsecret-123\n"),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run direct env: %v", err)
	}

	if !strings.Contains(stdout.String(), "Password: ") {
		t.Fatalf("expected password prompt, got %q", stdout.String())
	}
	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output: %v", err)
	}
}

func TestRunDirectDpxPromptsPasswordForDecrypt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("TOKEN=abc\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := run([]string{"encrypt", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt: %v", err)
	}
	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{sourcePath + ".dpx"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader("secret-123\n"),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run direct decrypt: %v", err)
	}

	if !strings.Contains(stdout.String(), "Password: ") {
		t.Fatalf("expected password prompt, got %q", stdout.String())
	}
	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunTUIAutoEncryptAndDecryptFlow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	encryptInput := strings.NewReader("4\n" + sourcePath + "\nsecret-123\nsecret-123\n\n")
	encryptOut := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{
		cwd:    dir,
		stdin:  encryptInput,
		stdout: encryptOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run tui auto encrypt: %v", err)
	}
	encryptedPath := sourcePath + ".dpx"
	if _, err := os.Stat(encryptedPath); err != nil {
		t.Fatalf("expected encrypted output: %v", err)
	}
	if !strings.Contains(encryptOut.String(), "File path (any file or .dpx)") {
		t.Fatalf("expected auto file prompt, got %q", encryptOut.String())
	}
	if !strings.Contains(encryptOut.String(), "Password: ") {
		t.Fatalf("expected password prompt, got %q", encryptOut.String())
	}

	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	decryptInput := strings.NewReader("4\n" + encryptedPath + "\nsecret-123\n\n")
	decryptOut := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{
		cwd:    dir,
		stdin:  decryptInput,
		stdout: decryptOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run tui auto decrypt: %v", err)
	}
	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch: got %q want %q", restored, plaintext)
	}
}

func TestRunTUIPasswordConfirmationMismatchCanRetry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	input := strings.NewReader("1\n1\n2\nsecret-123\nwrong-pass\nsecret-123\nsecret-123\n\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"tui"}, runOptions{
		cwd:    dir,
		stdin:  input,
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("expected retry flow to succeed, got %v", err)
	}

	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output after retry: %v", err)
	}
	if !strings.Contains(stdout.String(), "Password confirmation does not match") {
		t.Fatalf("expected mismatch hint in output, got %q", stdout.String())
	}
}

func TestRunEncryptPasswordConfirmationMismatchCanRetry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"encrypt", sourcePath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader("secret-123\nwrong\nsecret-123\nsecret-123\n"),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run encrypt retry flow: %v", err)
	}

	if _, err := os.Stat(sourcePath + ".dpx"); err != nil {
		t.Fatalf("expected encrypted output after retry: %v", err)
	}
	if !strings.Contains(stdout.String(), "Password confirmation does not match") {
		t.Fatalf("expected mismatch hint in output, got %q", stdout.String())
	}
	if strings.Count(stdout.String(), "Password: ") < 2 {
		t.Fatalf("expected password prompt to appear more than once, got %q", stdout.String())
	}
}

const envInlineCLIExample = `# Test Environment Variables
API_KEY=sk-secret-api-key-12345
DATABASE_URL=postgres://user:password@localhost:5432/mydb
JWT_SECRET=supersecretjwttoken
REDIS_PASSWORD=redis123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Comments are preserved
DEBUG=true
`

func TestRunEnvInlinePasswordEncryptDecrypt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte(envInlineCLIExample), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	encryptOut := new(bytes.Buffer)
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "password", "--keys", "API_KEY,JWT_SECRET,REDIS_PASSWORD", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: encryptOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run env encrypt password: %v", err)
	}
	if !strings.Contains(encryptOut.String(), "Updated keys (3)") {
		t.Fatalf("expected updated key count in output, got %q", encryptOut.String())
	}

	encryptedPath := sourcePath + ".dpx"
	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	encryptedText := string(encryptedData)
	if !strings.Contains(encryptedText, "API_KEY=ENC[v2:") || !strings.Contains(encryptedText, "JWT_SECRET=ENC[v2:") {
		t.Fatalf("expected inline password tokens, got %q", encryptedText)
	}
	if !strings.Contains(encryptedText, "DATABASE_URL=postgres://user:password@localhost:5432/mydb") {
		t.Fatalf("expected unselected key to remain plaintext")
	}

	restoredPath := filepath.Join(dir, ".env.restored")
	if err := run([]string{"env", "decrypt", encryptedPath, "--password", "secret-123", "--out", restoredPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run env decrypt password: %v", err)
	}
	restoredData, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restoredData) != envInlineCLIExample {
		t.Fatalf("restored mismatch\n--- got ---\n%s\n--- want ---\n%s", string(restoredData), envInlineCLIExample)
	}
}

func TestRunDecryptAutoHandlesInlineEncryptedEnv(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "password", "--keys", "API_KEY", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env encrypt inline: %v", err)
	}

	restoredPath := filepath.Join(dir, ".env.inline.dec")
	stdout := new(bytes.Buffer)
	if err := run([]string{"decrypt", sourcePath + ".dpx", "--password", "secret-123", "--out", restoredPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("decrypt inline via decrypt command: %v", err)
	}
	if !strings.Contains(stdout.String(), "Env inline decrypted") {
		t.Fatalf("expected inline decrypt output, got %q", stdout.String())
	}

	restoredData, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restoredData) != "API_KEY=abc123\nDEBUG=true\n" {
		t.Fatalf("restored mismatch: %q", string(restoredData))
	}
}

func TestRunDecryptOnPlaintextFileShowsClearError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("# Test Environment Variables\nAPI_KEY=plain\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := run([]string{"decrypt", sourcePath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatal("expected decrypt to fail for plaintext env file")
	}
	if !strings.Contains(err.Error(), "not a DPX envelope and no inline ENC tokens found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunEnvInlineAgeEncryptDecrypt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte(envInlineCLIExample), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	keyPath := filepath.Join(dir, "age-keys.txt")
	if err := run([]string{"keygen", "--out", keyPath}, runOptions{cwd: dir, stdin: strings.NewReader(""), stdout: new(bytes.Buffer), stderr: new(bytes.Buffer)}); err != nil {
		t.Fatalf("run keygen: %v", err)
	}

	encryptOut := new(bytes.Buffer)
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "age", "--keys", "API_KEY,JWT_SECRET"}, runOptions{cwd: dir, stdin: strings.NewReader(""), stdout: encryptOut, stderr: new(bytes.Buffer)}); err != nil {
		t.Fatalf("run env encrypt age: %v", err)
	}
	if !strings.Contains(encryptOut.String(), "Updated keys (2)") {
		t.Fatalf("expected updated key count in output, got %q", encryptOut.String())
	}

	encryptedPath := sourcePath + ".dpx"
	restoredPath := filepath.Join(dir, ".env.restored")
	if err := run([]string{"env", "decrypt", encryptedPath, "--out", restoredPath}, runOptions{cwd: dir, stdin: strings.NewReader(""), stdout: new(bytes.Buffer), stderr: new(bytes.Buffer)}); err != nil {
		t.Fatalf("run env decrypt age: %v", err)
	}
	restoredData, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restoredData) != envInlineCLIExample {
		t.Fatalf("restored mismatch\n--- got ---\n%s\n--- want ---\n%s", string(restoredData), envInlineCLIExample)
	}
}

func TestRunEnvInlineEncryptPromptsKeySelection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte(envInlineCLIExample), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	input := strings.NewReader("1,3\nsecret-123\nsecret-123\n")
	stdout := new(bytes.Buffer)
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "password"}, runOptions{cwd: dir, stdin: input, stdout: stdout, stderr: new(bytes.Buffer)}); err != nil {
		t.Fatalf("run env encrypt interactive key selection: %v", err)
	}
	if !strings.Contains(stdout.String(), "Select keys to encrypt") {
		t.Fatalf("expected key selection prompt, got %q", stdout.String())
	}
	data, err := os.ReadFile(sourcePath + ".dpx")
	if err != nil {
		t.Fatalf("read encrypted output: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "API_KEY=ENC[v2:") {
		t.Fatalf("expected API_KEY encrypted, got %q", text)
	}
	if !strings.Contains(text, "JWT_SECRET=supersecretjwttoken") {
		t.Fatalf("expected JWT_SECRET to remain plaintext for this selection")
	}
}

func TestRunCommandInjectsEnvFromEncryptedEnvelope(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DPX_HELPER_PRINT_ENV", "1")
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := run([]string{"encrypt", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("encrypt source: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os executable: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"run", sourcePath + ".dpx", "--password", "secret-123", "--", exe, "-test.run=TestDPXHelperPrintEnv", "--", "API_KEY"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run command: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "abc123" {
		t.Fatalf("expected injected API_KEY, got %q", got)
	}
}

func TestRunCommandInjectsEnvFromInlineEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DPX_HELPER_PRINT_ENV", "1")
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "password", "--keys", "API_KEY", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env encrypt: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os executable: %v", err)
	}

	stdout := new(bytes.Buffer)
	if err := run([]string{"run", sourcePath + ".dpx", "--password", "secret-123", "--", exe, "-test.run=TestDPXHelperPrintEnv", "--", "API_KEY"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("run command: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "abc123" {
		t.Fatalf("expected injected API_KEY, got %q", got)
	}
}

func TestRunPolicyCheckFailsOnPlaintextSensitiveKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=plain\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	stdout := new(bytes.Buffer)
	err := run([]string{"policy", "check", sourcePath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: new(bytes.Buffer),
	})
	if err == nil {
		t.Fatalf("expected policy check to fail")
	}
	if !strings.Contains(stdout.String(), "API_KEY") {
		t.Fatalf("expected output to mention API_KEY, got %q", stdout.String())
	}
}

func TestRunPolicyCheckPassesForEncryptedValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=ENC[v2:abc]\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"policy", "check", sourcePath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("expected policy check pass, got %v", err)
	}
}

func TestRunEnvListAndGetFromInlineEncryptedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "password", "--keys", "API_KEY", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env encrypt: %v", err)
	}

	listOut := new(bytes.Buffer)
	if err := run([]string{"env", "list", sourcePath + ".dpx", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: listOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env list: %v", err)
	}
	if !strings.Contains(listOut.String(), "API_KEY") || !strings.Contains(listOut.String(), "DEBUG") {
		t.Fatalf("expected keys in list output, got %q", listOut.String())
	}

	getOut := new(bytes.Buffer)
	if err := run([]string{"env", "get", sourcePath + ".dpx", "--key", "API_KEY", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: getOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env get: %v", err)
	}
	if got := strings.TrimSpace(getOut.String()); got != "abc123" {
		t.Fatalf("expected API_KEY value, got %q", got)
	}
}

func TestRunEnvSetEncryptedAndReadBack(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("DEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"env", "set", sourcePath, "--key", "API_KEY", "--value", "abc123", "--encrypt", "--mode", "password", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env set: %v", err)
	}

	updated, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read updated file: %v", err)
	}
	if !strings.Contains(string(updated), "API_KEY=ENC[v2:") {
		t.Fatalf("expected encrypted API_KEY token, got %q", string(updated))
	}

	getOut := new(bytes.Buffer)
	if err := run([]string{"env", "get", sourcePath, "--key", "API_KEY", "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: getOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env get from updated file: %v", err)
	}
	if got := strings.TrimSpace(getOut.String()); got != "abc123" {
		t.Fatalf("expected API_KEY value, got %q", got)
	}
}

func TestRunEnvEncryptUsesCreationRuleDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := `version: 1
default_suffix: ".dpx"
key_file: "~/.config/dpx/age-keys.txt"
age:
  recipients: []
discovery:
  include:
    - ".env"
policy:
  creation_rules:
    - path: ".env.production"
      mode: "password"
      encrypt_keys:
        - "API_KEY"
        - "JWT_SECRET"
`
	if err := os.WriteFile(filepath.Join(dir, ".dpx.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	sourcePath := filepath.Join(dir, ".env.production")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\nJWT_SECRET=jwt123\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := run([]string{"env", "encrypt", sourcePath, "--password", "secret-123"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env encrypt with creation rules: %v", err)
	}

	encryptedData, err := os.ReadFile(sourcePath + ".dpx")
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	encryptedText := string(encryptedData)
	if !strings.Contains(encryptedText, "API_KEY=ENC[v2:") {
		t.Fatalf("expected API_KEY to be encrypted by creation rule")
	}
	if !strings.Contains(encryptedText, "JWT_SECRET=ENC[v2:") {
		t.Fatalf("expected JWT_SECRET to be encrypted by creation rule")
	}
	if !strings.Contains(encryptedText, "DEBUG=true") {
		t.Fatalf("expected DEBUG to remain plaintext, got %q", encryptedText)
	}
}

func TestRunEnvUpdateKeysRotatesAgeRecipients(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	oldKeyPath := filepath.Join(dir, "old-age-keys.txt")
	if err := run([]string{"keygen", "--out", oldKeyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("keygen old identity: %v", err)
	}
	if err := run([]string{"env", "encrypt", sourcePath, "--mode", "age", "--keys", "API_KEY"}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env encrypt age: %v", err)
	}

	newIdentity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate new identity: %v", err)
	}
	newKeyPath := filepath.Join(dir, "new-age-keys.txt")
	if err := os.WriteFile(newKeyPath, []byte(newIdentity.PrivateKey+"\n"), 0o600); err != nil {
		t.Fatalf("write new key file: %v", err)
	}

	if err := run([]string{"env", "updatekeys", sourcePath + ".dpx", "--recipient", newIdentity.PublicKey, "--identity", oldKeyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env updatekeys: %v", err)
	}

	if err := run([]string{"env", "get", sourcePath + ".dpx", "--key", "API_KEY", "--identity", oldKeyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: new(bytes.Buffer),
		stderr: new(bytes.Buffer),
	}); err == nil {
		t.Fatal("expected old identity to fail after recipient rotation")
	}

	getOut := new(bytes.Buffer)
	if err := run([]string{"env", "get", sourcePath + ".dpx", "--key", "API_KEY", "--identity", newKeyPath}, runOptions{
		cwd:    dir,
		stdin:  strings.NewReader(""),
		stdout: getOut,
		stderr: new(bytes.Buffer),
	}); err != nil {
		t.Fatalf("env get with new identity: %v", err)
	}
	if got := strings.TrimSpace(getOut.String()); got != "abc123" {
		t.Fatalf("expected API_KEY value with new identity, got %q", got)
	}
}
