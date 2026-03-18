package app_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/crypto/password"
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
	if meta.EncryptionAlgorithm != "xchacha20poly1305" {
		t.Fatalf("expected xchacha20poly1305 algorithm metadata, got %q", meta.EncryptionAlgorithm)
	}
	if meta.EncryptionNonceB64 == "" {
		t.Fatal("expected encryption nonce metadata to be present")
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

func TestEncryptRejectsUnknownKDFProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, ".env")
	if err := os.WriteFile(sourcePath, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	_, err := svc.EncryptFile(app.EncryptRequest{
		InputPath:  sourcePath,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
		KDFProfile: "invalid-profile",
	})
	if err == nil {
		t.Fatal("expected unknown kdf profile to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "kdf profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptLegacyPasswordEnvelopeFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	legacyPath := filepath.Join(dir, ".env.legacy.dpx")
	plaintext := []byte("FOO=bar\n")
	originalMode := uint32(0o600)
	meta := envelope.Metadata{
		Version:          1,
		Mode:             envelope.ModePassword,
		OriginalName:     ".env",
		OriginalFileMode: &originalMode,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		PayloadEncoding:  "base64",
	}

	params, err := password.NewParams()
	if err != nil {
		t.Fatalf("new params: %v", err)
	}
	meta.KDF = &envelope.KDFParams{
		Algorithm:   "argon2id",
		SaltBase64:  base64.StdEncoding.EncodeToString(params.Salt),
		MemoryKiB:   params.MemoryKiB,
		Iterations:  params.Iterations,
		Parallelism: params.Parallelism,
	}
	protected, err := envelope.MarshalProtected(meta, plaintext)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}
	sealed, err := password.EncryptWithParams(protected, []byte("secret-123"), params)
	if err != nil {
		t.Fatalf("encrypt with params: %v", err)
	}
	payload := append(append([]byte{}, params.Nonce...), sealed...)
	encoded, err := envelope.Marshal(meta, payload)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(legacyPath, encoded, 0o600); err != nil {
		t.Fatalf("write legacy envelope: %v", err)
	}

	svc := app.New(config.Default())
	outputPath := filepath.Join(dir, ".env.dec")
	if _, err := svc.DecryptFile(app.DecryptRequest{
		InputPath:  legacyPath,
		OutputPath: outputPath,
		Passphrase: []byte("secret-123"),
	}); err != nil {
		t.Fatalf("decrypt legacy envelope: %v", err)
	}
	restored, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restored) != string(plaintext) {
		t.Fatalf("legacy restore mismatch: got %q want %q", restored, plaintext)
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

const envInlineSample = `# Test Environment Variables
API_KEY=sk-secret-api-key-12345
DATABASE_URL=postgres://user:password@localhost:5432/mydb
JWT_SECRET=supersecretjwttoken
REDIS_PASSWORD=redis123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Comments are preserved
DEBUG=true
`

func TestEnvInlinePasswordRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(envInlineSample), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	svc := app.New(config.Default())
	encrypted, err := svc.EncryptEnvInlineFile(app.EnvInlineEncryptRequest{
		InputPath:    path,
		Mode:         envelope.ModePassword,
		Passphrase:   []byte("secret-123"),
		SelectedKeys: []string{"API_KEY", "JWT_SECRET", "REDIS_PASSWORD"},
	})
	if err != nil {
		t.Fatalf("encrypt inline env: %v", err)
	}
	if len(encrypted.Updated) != 3 {
		t.Fatalf("expected 3 updated keys, got %#v", encrypted.Updated)
	}

	content, err := os.ReadFile(encrypted.OutputPath)
	if err != nil {
		t.Fatalf("read encrypted output: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "API_KEY=ENC[v2:") || !strings.Contains(text, "JWT_SECRET=ENC[v2:") {
		t.Fatalf("expected selected keys to be inline encrypted, got %q", text)
	}
	if !strings.Contains(text, "DATABASE_URL=postgres://user:password@localhost:5432/mydb") {
		t.Fatalf("expected unselected key to remain plaintext")
	}

	decrypted, err := svc.DecryptEnvInlineFile(app.EnvInlineDecryptRequest{
		InputPath:  encrypted.OutputPath,
		Passphrase: []byte("secret-123"),
		OutputPath: filepath.Join(dir, ".env.restored"),
	})
	if err != nil {
		t.Fatalf("decrypt inline env: %v", err)
	}
	if len(decrypted.Updated) != 3 {
		t.Fatalf("expected 3 decrypted keys, got %#v", decrypted.Updated)
	}

	restored, err := os.ReadFile(decrypted.OutputPath)
	if err != nil {
		t.Fatalf("read restored output: %v", err)
	}
	if string(restored) != envInlineSample {
		t.Fatalf("restored mismatch\n--- got ---\n%s\n--- want ---\n%s", string(restored), envInlineSample)
	}
}

func TestEnvInlineAgeRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(envInlineSample), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	svc := app.New(config.Config{Age: config.AgeConfig{Recipients: []string{identity.PublicKey}}, DefaultSuffix: ".dpx", KeyFile: filepath.Join(dir, "age-keys.txt"), Version: 1, Discovery: config.Default().Discovery})
	if err := os.WriteFile(filepath.Join(dir, "age-keys.txt"), []byte(identity.PrivateKey+"\n"), 0o600); err != nil {
		t.Fatalf("write age key: %v", err)
	}

	encrypted, err := svc.EncryptEnvInlineFile(app.EnvInlineEncryptRequest{
		InputPath:    path,
		Mode:         envelope.ModeAge,
		SelectedKeys: []string{"API_KEY", "JWT_SECRET"},
	})
	if err != nil {
		t.Fatalf("encrypt age inline env: %v", err)
	}
	if len(encrypted.Updated) != 2 {
		t.Fatalf("expected 2 updated keys, got %#v", encrypted.Updated)
	}

	mAge, mPwd, err := svc.DetectEnvInlineModes(encrypted.OutputPath)
	if err != nil {
		t.Fatalf("detect env inline modes: %v", err)
	}
	if !mAge || mPwd {
		t.Fatalf("expected age=true password=false, got age=%v password=%v", mAge, mPwd)
	}

	decrypted, err := svc.DecryptEnvInlineFile(app.EnvInlineDecryptRequest{
		InputPath:  encrypted.OutputPath,
		OutputPath: filepath.Join(dir, ".env.restored"),
	})
	if err != nil {
		t.Fatalf("decrypt age inline env: %v", err)
	}
	if len(decrypted.Updated) != 2 {
		t.Fatalf("expected 2 decrypted keys, got %#v", decrypted.Updated)
	}

	restored, err := os.ReadFile(decrypted.OutputPath)
	if err != nil {
		t.Fatalf("read restored output: %v", err)
	}
	if string(restored) != envInlineSample {
		t.Fatalf("restored mismatch\n--- got ---\n%s\n--- want ---\n%s", string(restored), envInlineSample)
	}
}
