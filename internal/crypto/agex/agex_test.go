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
