package app_test

import (
	"bytes"
	"os"
	"path/filepath"
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
