package envcrypt_test

import (
	"strings"
	"testing"

	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/envcrypt"
	"github.com/dwirx/dpx/internal/envelope"
)

const sampleEnv = `# Test Environment Variables
API_KEY=sk-secret-api-key-12345
DATABASE_URL=postgres://user:password@localhost:5432/mydb
JWT_SECRET=supersecretjwttoken
REDIS_PASSWORD=redis123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Comments are preserved
DEBUG=true
`

func TestEncryptDecryptAgeSelectedKeysRoundTrip(t *testing.T) {
	t.Parallel()

	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	encrypted, result, err := envcrypt.Encrypt([]byte(sampleEnv), envcrypt.EncryptRequest{
		Mode:       envelope.ModeAge,
		Recipients: []string{identity.PublicKey},
		SelectedKeys: []string{
			"API_KEY",
			"DB_PASSWORD", // intentionally absent to verify ignore
			"JWT_SECRET",
		},
	})
	if err != nil {
		t.Fatalf("encrypt env: %v", err)
	}
	if len(result.UpdatedKeys) != 2 {
		t.Fatalf("expected 2 updated keys, got %#v", result.UpdatedKeys)
	}

	out := string(encrypted)
	if !strings.Contains(out, "API_KEY=ENC[age:") {
		t.Fatalf("expected API_KEY to be age encrypted, got %q", out)
	}
	if !strings.Contains(out, "JWT_SECRET=ENC[age:") {
		t.Fatalf("expected JWT_SECRET to be age encrypted, got %q", out)
	}
	if !strings.Contains(out, "DATABASE_URL=postgres://user:password@localhost:5432/mydb") {
		t.Fatalf("expected DATABASE_URL unchanged")
	}
	if !strings.Contains(out, "# Comments are preserved") {
		t.Fatalf("expected comments to be preserved")
	}

	decrypted, decResult, err := envcrypt.Decrypt(encrypted, envcrypt.DecryptRequest{PrivateKey: identity.PrivateKey})
	if err != nil {
		t.Fatalf("decrypt env: %v", err)
	}
	if len(decResult.UpdatedKeys) != 2 {
		t.Fatalf("expected 2 decrypted keys, got %#v", decResult.UpdatedKeys)
	}
	if string(decrypted) != sampleEnv {
		t.Fatalf("roundtrip mismatch\n--- got ---\n%s\n--- want ---\n%s", string(decrypted), sampleEnv)
	}
}

func TestEncryptDecryptPasswordRoundTrip(t *testing.T) {
	t.Parallel()

	encrypted, result, err := envcrypt.Encrypt([]byte(sampleEnv), envcrypt.EncryptRequest{
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
		SelectedKeys: []string{
			"API_KEY",
			"REDIS_PASSWORD",
		},
	})
	if err != nil {
		t.Fatalf("encrypt env: %v", err)
	}
	if len(result.UpdatedKeys) != 2 {
		t.Fatalf("expected 2 updated keys, got %#v", result.UpdatedKeys)
	}

	out := string(encrypted)
	if !strings.Contains(out, "API_KEY=ENC[pwd:v1:") {
		t.Fatalf("expected API_KEY to be password encrypted")
	}
	if !strings.Contains(out, "REDIS_PASSWORD=ENC[pwd:v1:") {
		t.Fatalf("expected REDIS_PASSWORD to be password encrypted")
	}

	decrypted, decResult, err := envcrypt.Decrypt(encrypted, envcrypt.DecryptRequest{Passphrase: []byte("secret-123")})
	if err != nil {
		t.Fatalf("decrypt env: %v", err)
	}
	if len(decResult.UpdatedKeys) != 2 {
		t.Fatalf("expected 2 decrypted keys, got %#v", decResult.UpdatedKeys)
	}
	if string(decrypted) != sampleEnv {
		t.Fatalf("roundtrip mismatch\n--- got ---\n%s\n--- want ---\n%s", string(decrypted), sampleEnv)
	}
}

func TestDetectModesAndListEncryptableKeys(t *testing.T) {
	t.Parallel()

	keys := envcrypt.ListEncryptableKeys([]byte(sampleEnv))
	if len(keys) == 0 {
		t.Fatal("expected encryptable keys")
	}
	if !contains(keys, "API_KEY") || !contains(keys, "DEBUG") {
		t.Fatalf("expected API_KEY and DEBUG in key list, got %#v", keys)
	}

	withToken := strings.Replace(sampleEnv, "API_KEY=sk-secret-api-key-12345", "API_KEY=ENC[age:abc]", 1)
	hasAge, hasPwd := envcrypt.DetectModes([]byte(withToken))
	if !hasAge || hasPwd {
		t.Fatalf("expected age=true password=false, got age=%v password=%v", hasAge, hasPwd)
	}
}

func TestSetAddsEncryptedKey(t *testing.T) {
	t.Parallel()

	out, result, err := envcrypt.Set([]byte("DEBUG=true\n"), envcrypt.SetRequest{
		Key:        "API_KEY",
		Value:      "abc123",
		Encrypt:    true,
		Mode:       envelope.ModePassword,
		Passphrase: []byte("secret-123"),
	})
	if err != nil {
		t.Fatalf("set key: %v", err)
	}
	if len(result.UpdatedKeys) != 1 || result.UpdatedKeys[0] != "API_KEY" {
		t.Fatalf("unexpected updated keys: %#v", result.UpdatedKeys)
	}
	if !strings.Contains(string(out), "API_KEY=ENC[pwd:v1:") {
		t.Fatalf("expected encrypted API_KEY, got %q", string(out))
	}
}

func TestSetUpdatesExistingKeyPlaintext(t *testing.T) {
	t.Parallel()

	out, _, err := envcrypt.Set([]byte("API_KEY=old\n"), envcrypt.SetRequest{
		Key:   "API_KEY",
		Value: "new",
	})
	if err != nil {
		t.Fatalf("set key: %v", err)
	}
	if string(out) != "API_KEY=new\n" {
		t.Fatalf("unexpected output: %q", string(out))
	}
}

func TestUpdateAgeRecipientsReEncryptsTokens(t *testing.T) {
	t.Parallel()

	oldIdentity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate old identity: %v", err)
	}
	newIdentity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate new identity: %v", err)
	}

	encrypted, _, err := envcrypt.Encrypt([]byte("API_KEY=abc123\n"), envcrypt.EncryptRequest{
		Mode:       envelope.ModeAge,
		Recipients: []string{oldIdentity.PublicKey},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	updated, result, err := envcrypt.UpdateAgeRecipients(encrypted, envcrypt.UpdateRecipientsRequest{
		PrivateKey: oldIdentity.PrivateKey,
		Recipients: []string{newIdentity.PublicKey},
	})
	if err != nil {
		t.Fatalf("update recipients: %v", err)
	}
	if len(result.UpdatedKeys) != 1 || result.UpdatedKeys[0] != "API_KEY" {
		t.Fatalf("unexpected updated keys: %#v", result.UpdatedKeys)
	}

	if _, _, err := envcrypt.Decrypt(updated, envcrypt.DecryptRequest{PrivateKey: oldIdentity.PrivateKey}); err == nil {
		t.Fatal("expected old identity decryption to fail after recipient rotation")
	}
	decrypted, _, err := envcrypt.Decrypt(updated, envcrypt.DecryptRequest{PrivateKey: newIdentity.PrivateKey})
	if err != nil {
		t.Fatalf("decrypt with new identity: %v", err)
	}
	if string(decrypted) != "API_KEY=abc123\n" {
		t.Fatalf("unexpected decrypted output: %q", string(decrypted))
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
