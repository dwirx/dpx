package password

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSize = chacha20poly1305.NonceSizeX
	KeySize   = chacha20poly1305.KeySize

	maxMemoryKiB   = 256 * 1024
	maxIterations  = 10
	maxParallelism = 8
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
		Nonce:       make([]byte, NonceSize),
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: uint8(parallelism),
		KeyLength:   KeySize,
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
	if params.KeyLength == 0 {
		params.KeyLength = KeySize
	}
	if err := ValidateParams(params); err != nil {
		return nil, err
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
	if params.KeyLength == 0 {
		params.KeyLength = KeySize
	}
	if err := ValidateParams(params); err != nil {
		return nil, err
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

func ValidateParams(params Params) error {
	if len(params.Salt) < 16 {
		return errors.New("invalid params: salt is too short")
	}
	if len(params.Nonce) != NonceSize {
		return errors.New("invalid params: nonce size mismatch")
	}
	if params.Iterations == 0 || params.Iterations > maxIterations {
		return fmt.Errorf("invalid params: iterations must be between 1 and %d", maxIterations)
	}
	if params.Parallelism == 0 || params.Parallelism > maxParallelism {
		return fmt.Errorf("invalid params: parallelism must be between 1 and %d", maxParallelism)
	}
	minMemory := uint32(params.Parallelism) * 8
	if params.MemoryKiB < minMemory || params.MemoryKiB > maxMemoryKiB {
		return fmt.Errorf("invalid params: memory must be between %d and %d KiB", minMemory, maxMemoryKiB)
	}
	if params.KeyLength != KeySize {
		return fmt.Errorf("invalid params: key length must be %d bytes", KeySize)
	}
	return nil
}
