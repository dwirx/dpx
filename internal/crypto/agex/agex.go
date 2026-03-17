package agex

import (
	"bytes"
	"fmt"
	"strings"

	"filippo.io/age"
)

type Identity struct {
	PublicKey  string
	PrivateKey string
}

func GenerateIdentity() (Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return Identity{}, fmt.Errorf("generate x25519 identity: %w", err)
	}
	return Identity{
		PublicKey:  identity.Recipient().String(),
		PrivateKey: identity.String(),
	}, nil
}

func IdentityFromPrivateData(data string) (Identity, error) {
	identities, err := age.ParseIdentities(strings.NewReader(data))
	if err != nil {
		return Identity{}, fmt.Errorf("parse identities: %w", err)
	}
	for _, parsed := range identities {
		x25519, ok := parsed.(*age.X25519Identity)
		if !ok {
			continue
		}
		return Identity{
			PublicKey:  x25519.Recipient().String(),
			PrivateKey: x25519.String(),
		}, nil
	}
	return Identity{}, fmt.Errorf("no x25519 private key found")
}

func Encrypt(plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	parsedRecipients := make([]age.Recipient, 0, len(recipients))
	for _, recipient := range recipients {
		parsed, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", recipient, err)
		}
		parsedRecipients = append(parsedRecipients, parsed)
	}

	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, parsedRecipients...)
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finalize age payload: %w", err)
	}
	return buf.Bytes(), nil
}

func Decrypt(sealed []byte, privateKey string) ([]byte, error) {
	identities, err := age.ParseIdentities(strings.NewReader(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	reader, err := age.Decrypt(bytes.NewReader(sealed), identities...)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	plaintext := new(bytes.Buffer)
	if _, err := plaintext.ReadFrom(reader); err != nil {
		return nil, fmt.Errorf("read decrypted payload: %w", err)
	}
	return plaintext.Bytes(), nil
}
