package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dopx/internal/config"
	"dopx/internal/crypto/agex"
	"dopx/internal/crypto/password"
	"dopx/internal/discovery"
	"dopx/internal/envelope"
)

type Service struct {
	cfg config.Config
}

type EncryptRequest struct {
	InputPath  string
	OutputPath string
	Mode       string
	Passphrase []byte
	Recipients []string
}

type DecryptRequest struct {
	InputPath    string
	OutputPath   string
	Passphrase   []byte
	IdentityPath string
	PrivateKey   string
}

func New(cfg config.Config) Service {
	return Service{cfg: cfg}
}

func (s Service) Init(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return config.Save(path, s.cfg)
}

func (s Service) Keygen(path string) (agex.Identity, error) {
	identity, err := agex.GenerateIdentity()
	if err != nil {
		return agex.Identity{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return agex.Identity{}, err
	}
	if err := os.WriteFile(path, []byte(identity.PrivateKey+"\n"), 0o600); err != nil {
		return agex.Identity{}, err
	}
	return identity, nil
}

func (s Service) Discover(root string) ([]discovery.Candidate, error) {
	return discovery.FindCandidates(root)
}

func (s Service) EncryptFile(req EncryptRequest) (string, error) {
	if req.InputPath == "" {
		return "", fmt.Errorf("input path is required")
	}
	plaintext, err := os.ReadFile(req.InputPath)
	if err != nil {
		return "", err
	}

	meta := envelope.Metadata{
		Version:         1,
		Mode:            req.Mode,
		OriginalName:    filepath.Base(req.InputPath),
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
		PayloadEncoding: "base64",
	}

	var payload []byte
	switch req.Mode {
	case envelope.ModePassword:
		params, err := password.NewParams()
		if err != nil {
			return "", err
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
			return "", err
		}
		sealed, err := password.EncryptWithParams(protected, req.Passphrase, params)
		if err != nil {
			return "", err
		}
		payload = append(append([]byte{}, params.Nonce...), sealed...)
	case envelope.ModeAge:
		recipients := req.Recipients
		if len(recipients) == 0 {
			recipients = s.cfg.Age.Recipients
		}
		protected, err := envelope.MarshalProtected(meta, plaintext)
		if err != nil {
			return "", err
		}
		sealed, err := agex.Encrypt(protected, recipients)
		if err != nil {
			return "", err
		}
		payload = sealed
	default:
		return "", fmt.Errorf("unsupported mode %q", req.Mode)
	}

	encoded, err := envelope.Marshal(meta, payload)
	if err != nil {
		return "", err
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = req.InputPath + s.cfg.DefaultSuffix
	}
	if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
		return "", err
	}
	return outputPath, nil
}

func (s Service) Inspect(path string) (envelope.Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return envelope.Metadata{}, err
	}
	meta, _, err := envelope.Unmarshal(data)
	return meta, err
}

func (s Service) DecryptFile(req DecryptRequest) (string, error) {
	if req.InputPath == "" {
		return "", fmt.Errorf("input path is required")
	}
	data, err := os.ReadFile(req.InputPath)
	if err != nil {
		return "", err
	}
	meta, payload, err := envelope.Unmarshal(data)
	if err != nil {
		return "", err
	}

	var protected []byte
	switch meta.Mode {
	case envelope.ModePassword:
		if meta.KDF == nil {
			return "", fmt.Errorf("password metadata missing")
		}
		salt, err := base64.StdEncoding.DecodeString(meta.KDF.SaltBase64)
		if err != nil {
			return "", fmt.Errorf("decode salt: %w", err)
		}
		if len(payload) < 24 {
			return "", fmt.Errorf("malformed password payload")
		}
		params := password.Params{
			Salt:        salt,
			Nonce:       append([]byte{}, payload[:24]...),
			MemoryKiB:   meta.KDF.MemoryKiB,
			Iterations:  meta.KDF.Iterations,
			Parallelism: meta.KDF.Parallelism,
			KeyLength:   32,
		}
		protected, err = password.Decrypt(payload[24:], req.Passphrase, params)
		if err != nil {
			return "", err
		}
	case envelope.ModeAge:
		privateKey, err := s.resolvePrivateKey(req)
		if err != nil {
			return "", err
		}
		protected, err = agex.Decrypt(payload, privateKey)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported mode %q", meta.Mode)
	}

	plaintext, err := envelope.UnmarshalProtected(meta, protected)
	if err != nil {
		return "", err
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(filepath.Dir(req.InputPath), filepath.Base(meta.OriginalName))
	}
	if err := os.WriteFile(outputPath, plaintext, 0o600); err != nil {
		return "", err
	}
	return outputPath, nil
}

func (s Service) resolvePrivateKey(req DecryptRequest) (string, error) {
	if strings.TrimSpace(req.PrivateKey) != "" {
		return req.PrivateKey, nil
	}
	path := req.IdentityPath
	if path == "" {
		path = s.cfg.KeyFile
	}
	expanded := expandHome(path)
	data, err := os.ReadFile(expanded)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && path == config.DefaultKeyFile {
			legacyPath := expandHome(config.LegacyKeyFile)
			legacyData, legacyErr := os.ReadFile(legacyPath)
			if legacyErr == nil {
				return string(legacyData), nil
			}
		}
		return "", err
	}
	return string(data), nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
