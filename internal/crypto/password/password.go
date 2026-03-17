package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type Params struct {
	Salt        []byte
	Nonce       []byte
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
}

func DefaultParams() Params {
	parallelism := runtime.NumCPU()
	if parallelism < 2 {
		parallelism = 2
	}
	if parallelism > 4 {
		parallelism = 4
	}
	return Params{
		Salt:        make([]byte, 16),
		Nonce:       make([]byte, chacha20poly1305.NonceSizeX),
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: uint8(parallelism),
		KeyLength:   chacha20poly1305.KeySize,
	}
}

func NewParams() (Params, error) {
	params := DefaultParams()
	if _, err := rand.Read(params.Salt); err != nil {
		return Params{}, fmt.Errorf("read salt: %w", err)
	}
	if _, err := rand.Read(params.Nonce); err != nil {
		return Params{}, fmt.Errorf("read nonce: %w", err)
	}
	return params, nil
}

func Encrypt(plaintext, passphrase []byte) ([]byte, Params, error) {
	params, err := NewParams()
	if err != nil {
		return nil, Params{}, err
	}
	sealed, err := EncryptWithParams(plaintext, passphrase, params)
	if err != nil {
		return nil, Params{}, err
	}
	return sealed, params, nil
}

func EncryptWithParams(plaintext, passphrase []byte, params Params) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is required")
	}
	if len(params.Salt) == 0 || len(params.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid params")
	}
	if params.KeyLength == 0 {
		params.KeyLength = chacha20poly1305.KeySize
	}

	key := argon2.IDKey(passphrase, params.Salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	return aead.Seal(nil, params.Nonce, plaintext, nil), nil
}

func Decrypt(sealed, passphrase []byte, params Params) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is required")
	}
	if len(params.Salt) == 0 || len(params.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid params")
	}
	if params.KeyLength == 0 {
		params.KeyLength = chacha20poly1305.KeySize
	}

	key := argon2.IDKey(passphrase, params.Salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyLength)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}
	opened, err := aead.Open(nil, params.Nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return opened, nil
}
