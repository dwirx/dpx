package app_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/envelope"
)

func TestInitCreatesDefaultConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	svc := app.New(config.Default())
	path := filepath.Join(dir, ".dpx.yaml")

	if err := svc.Init(path); err != nil {
		t.Fatalf("init: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config file: %v", err)
	}
}

func TestKeygenStoresPrivateAndPublicInKeyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age-keys.txt")
	svc := app.New(config.Default())

	identity, err := svc.Keygen(keyPath)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, identity.PrivateKey) {
		t.Fatalf("expected private key in key file")
	}
	if !strings.Contains(text, identity.PublicKey) {
		t.Fatalf("expected public key in key file")
	}
	if !strings.Contains(text, "# public key: "+identity.PublicKey) {
		t.Fatalf("expected public key comment format, got %q", text)
	}
}

func TestPasswordEncryptInspectDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	plaintext := []byte("FOO=bar\nHELLO=world\n")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove plaintext: %v", err)
	}

	meta, err := svc.Inspect(encryptedPath)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if meta.Mode != envelope.ModePassword {
		t.Fatalf("mode mismatch: got %q", meta.Mode)
	}

	restoredPath, err := svc.DecryptFile(app.DecryptRequest{
		InputPath:  encryptedPath,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("decrypt file: %v", err)
	}
	if restoredPath != sourcePath {
		t.Fatalf("restore path mismatch: got %q want %q", restoredPath, sourcePath)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored plaintext mismatch: got %q want %q", restored, plaintext)
	}
}

func TestPasswordEncryptDecryptPreservesOriginalFileMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "tool.bin")
	plaintext := []byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02, 0x03}
	if err := os.WriteFile(sourcePath, plaintext, 0o755); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	if err := os.Remove(sourcePath); err != nil {
		t.Fatalf("remove source: %v", err)
	}

	restoredPath, err := svc.DecryptFile(app.DecryptRequest{
		InputPath:  encryptedPath,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("decrypt file: %v", err)
	}
	if restoredPath != sourcePath {
		t.Fatalf("restore path mismatch: got %q want %q", restoredPath, sourcePath)
	}

	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored plaintext mismatch: got %v want %v", restored, plaintext)
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatalf("expected mode 0755, got %04o", info.Mode().Perm())
	}
}

func TestDecryptRejectsTamperedMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	tampered := strings.Replace(string(data), "Original-Name: .env", "Original-Name: prod.env", 1)
	if err := os.WriteFile(encryptedPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	if _, err := svc.DecryptFile(app.DecryptRequest{InputPath: encryptedPath, Passphrase: []byte("secret-123")}); err == nil {
		t.Fatal("expected tampered metadata to fail decryption")
	}
}

func TestDecryptRejectsUnsupportedKDFAlgorithm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	tampered := strings.Replace(string(data), "KDF-Algorithm: argon2id", "KDF-Algorithm: scrypt", 1)
	if err := os.WriteFile(encryptedPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	_, err = svc.DecryptFile(app.DecryptRequest{InputPath: encryptedPath, Passphrase: []byte("secret-123")})
	if err == nil {
		t.Fatal("expected unsupported kdf algorithm to fail decryption")
	}
	if !strings.Contains(err.Error(), "unsupported kdf algorithm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptRejectsInvalidKDFParallelism(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	meta, _, err := envelope.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal encrypted file: %v", err)
	}
	originalLine := fmt.Sprintf("KDF-Parallelism: %d", meta.KDF.Parallelism)
	tampered := strings.Replace(string(data), originalLine, "KDF-Parallelism: 0", 1)
	if strings.Contains(tampered, originalLine) {
		t.Fatalf("failed to tamper KDF parallelism in payload")
	}
	if err := os.WriteFile(encryptedPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered file: %v", err)
	}

	_, err = svc.DecryptFile(app.DecryptRequest{InputPath: encryptedPath, Passphrase: []byte("secret-123")})
	if err == nil {
		t.Fatal("expected invalid parallelism to fail decryption")
	}
	if !strings.Contains(err.Error(), "parallelism") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptRejectsSymlinkOutputPath(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is platform-specific on windows")
	}

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	targetPath := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkPath := filepath.Join(dir, "out.dpx")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	svc := app.New(config.Default())
	_, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		OutputPath: linkPath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err == nil {
		t.Fatal("expected symlink output to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}

	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("target file was modified via symlink: %q", got)
	}
}

func TestDecryptRejectsSymlinkOutputPath(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is platform-specific on windows")
	}

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encryptedPath, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("encrypt file: %v", err)
	}

	targetPath := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkPath := filepath.Join(dir, "restored.env")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err = svc.DecryptFile(app.DecryptRequest{
		InputPath:  encryptedPath,
		OutputPath: linkPath,
		Passphrase: []byte("secret-123"),
	})
	if err == nil {
		t.Fatal("expected symlink output to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}

	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("target file was modified via symlink: %q", got)
	}
}

func TestKeygenRejectsSymlinkKeyPath(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior is platform-specific on windows")
	}

	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkPath := filepath.Join(dir, "age-keys.txt")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	svc := app.New(config.Default())
	if _, err := svc.Keygen(linkPath); err == nil {
		t.Fatal("expected symlink key path to be rejected")
	} else if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}

	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("target file was modified via symlink: %q", got)
	}
}
