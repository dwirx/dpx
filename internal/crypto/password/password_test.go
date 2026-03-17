package password_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dwirx/dpx/internal/crypto/password"
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

func TestDecryptRejectsInvalidKDFParams(t *testing.T) {
	t.Parallel()

	sealed, params, err := password.Encrypt([]byte("FOO=bar\n"), []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(p *password.Params)
		want   string
	}{
		{
			name: "zero iterations",
			mutate: func(p *password.Params) {
				p.Iterations = 0
			},
			want: "iterations",
		},
		{
			name: "zero parallelism",
			mutate: func(p *password.Params) {
				p.Parallelism = 0
			},
			want: "parallelism",
		},
		{
			name: "too large memory",
			mutate: func(p *password.Params) {
				p.MemoryKiB = 512 * 1024
			},
			want: "memory",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bad := params
			tc.mutate(&bad)
			_, err := password.Decrypt(sealed, []byte("secret"), bad)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error mismatch: got %q want substring %q", err, tc.want)
			}
		})
	}
}
