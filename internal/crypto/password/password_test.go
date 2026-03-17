package password_test

import (
	"bytes"
	"testing"

	"dopx/internal/crypto/password"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	plaintext := []byte("FOO=bar\nHELLO=world\n")
	passphrase := []byte("correct horse battery staple")

	sealed, params, err := password.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	opened, err := password.Decrypt(sealed, passphrase, params)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}
}

func TestDecryptRejectsWrongPassphrase(t *testing.T) {
	t.Parallel()

	sealed, params, err := password.Encrypt([]byte("FOO=bar\n"), []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := password.Decrypt(sealed, []byte("wrong"), params); err == nil {
		t.Fatal("expected wrong password to fail")
	}
}
