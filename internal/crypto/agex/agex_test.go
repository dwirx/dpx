package agex_test

import (
	"bytes"
	"testing"

	"github.com/dwirx/dpx/internal/crypto/agex"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	plaintext := []byte("FOO=bar\nHELLO=world\n")
	sealed, err := agex.Encrypt(plaintext, []string{identity.PublicKey})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	opened, err := agex.Decrypt(sealed, identity.PrivateKey)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}
}

func TestIdentityFromPrivateDataParsesCommentsAndKeys(t *testing.T) {
	t.Parallel()

	identity, err := agex.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	raw := "# created: 2026-03-17T11:00:00Z\n# public key: " + identity.PublicKey + "\n" + identity.PrivateKey + "\n"
	parsed, err := agex.IdentityFromPrivateData(raw)
	if err != nil {
		t.Fatalf("parse identity from data: %v", err)
	}
	if parsed.PublicKey != identity.PublicKey {
		t.Fatalf("public key mismatch: got %q want %q", parsed.PublicKey, identity.PublicKey)
	}
	if parsed.PrivateKey != identity.PrivateKey {
		t.Fatalf("private key mismatch: got %q want %q", parsed.PrivateKey, identity.PrivateKey)
	}
}
