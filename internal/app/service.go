package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/crypto/password"
	"github.com/dwirx/dpx/internal/discovery"
	"github.com/dwirx/dpx/internal/envcrypt"
	"github.com/dwirx/dpx/internal/envelope"
	"github.com/dwirx/dpx/internal/safeio"
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

type EnvInlineEncryptRequest struct {
	InputPath    string
	OutputPath   string
	Mode         string
	Passphrase   []byte
	Recipients   []string
	SelectedKeys []string
}

type EnvInlineDecryptRequest struct {
	InputPath    string
	OutputPath   string
	Passphrase   []byte
	IdentityPath string
	PrivateKey   string
}

type EnvInlineResult struct {
	OutputPath string
	Updated    []string
}

func New(cfg config.Config) Service {
	return Service{cfg: cfg}
}

func (s Service) Init(path string) error {
	if _, err := safeio.Stat(path); err == nil {
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
	if err := writeIdentityFile(path, identity); err != nil {
		return agex.Identity{}, err
	}
	return identity, nil
}

func (s Service) ImportIdentity(path, raw string) (agex.Identity, error) {
	identity, err := agex.IdentityFromPrivateData(raw)
	if err != nil {
		return agex.Identity{}, err
	}
	if err := writeIdentityFile(path, identity); err != nil {
		return agex.Identity{}, err
	}
	return identity, nil
}

func writeIdentityFile(path string, identity agex.Identity) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	keyData := strings.Join([]string{
		"# created: " + time.Now().UTC().Format(time.RFC3339),
		"# public key: " + identity.PublicKey,
		identity.PrivateKey,
		"",
	}, "\n")
	if err := safeio.WriteFile(path, []byte(keyData), 0o600); err != nil {
		return err
	}
	return nil
}

func (s Service) ReadIdentity(path string) (agex.Identity, error) {
	data, err := safeio.ReadFile(path)
	if err != nil {
		return agex.Identity{}, err
	}
	return agex.IdentityFromPrivateData(string(data))
}

func (s Service) Discover(root string) ([]discovery.Candidate, error) {
	return discovery.FindCandidates(root)
}

func (s Service) DiscoverEncryptTargets(root string) ([]discovery.Candidate, error) {
	return discovery.FindEncryptTargets(root)
}

func (s Service) ListEnvInlineKeys(path string) ([]string, error) {
	data, err := safeio.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return envcrypt.ListEncryptableKeys(data), nil
}

func (s Service) DetectEnvInlineModes(path string) (bool, bool, error) {
	data, err := safeio.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	hasAge, hasPassword := envcrypt.DetectModes(data)
	return hasAge, hasPassword, nil
}

func (s Service) EncryptEnvInlineFile(req EnvInlineEncryptRequest) (EnvInlineResult, error) {
	if req.InputPath == "" {
		return EnvInlineResult{}, fmt.Errorf("input path is required")
	}
	data, err := safeio.ReadFile(req.InputPath)
	if err != nil {
		return EnvInlineResult{}, err
	}

	encryptReq := envcrypt.EncryptRequest{
		Mode:         req.Mode,
		Passphrase:   req.Passphrase,
		Recipients:   req.Recipients,
		SelectedKeys: req.SelectedKeys,
	}
	if encryptReq.Mode == envelope.ModeAge && len(encryptReq.Recipients) == 0 {
		encryptReq.Recipients = append([]string{}, s.cfg.Age.Recipients...)
	}

	encrypted, report, err := envcrypt.Encrypt(data, encryptReq)
	if err != nil {
		return EnvInlineResult{}, err
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = req.InputPath + s.cfg.DefaultSuffix
	}
	if err := writeFileSecure(outputPath, encrypted, 0o600); err != nil {
		return EnvInlineResult{}, err
	}
	return EnvInlineResult{OutputPath: outputPath, Updated: report.UpdatedKeys}, nil
}

func (s Service) DecryptEnvInlineFile(req EnvInlineDecryptRequest) (EnvInlineResult, error) {
	if req.InputPath == "" {
		return EnvInlineResult{}, fmt.Errorf("input path is required")
	}
	data, err := safeio.ReadFile(req.InputPath)
	if err != nil {
		return EnvInlineResult{}, err
	}
	hasAge, hasPassword := envcrypt.DetectModes(data)

	privateKey := strings.TrimSpace(req.PrivateKey)
	if hasAge && privateKey == "" {
		privateKey, err = s.resolvePrivateKey(DecryptRequest{
			IdentityPath: req.IdentityPath,
			PrivateKey:   req.PrivateKey,
		})
		if err != nil {
			return EnvInlineResult{}, err
		}
	}
	if hasPassword && len(req.Passphrase) == 0 {
		return EnvInlineResult{}, fmt.Errorf("passphrase is required for password inline tokens")
	}

	decrypted, report, err := envcrypt.Decrypt(data, envcrypt.DecryptRequest{
		PrivateKey: privateKey,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		return EnvInlineResult{}, err
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = defaultInlineDecryptOutputPath(req.InputPath, s.cfg.DefaultSuffix)
	}
	if err := writeFileSecure(outputPath, decrypted, 0o600); err != nil {
		return EnvInlineResult{}, err
	}
	return EnvInlineResult{OutputPath: outputPath, Updated: report.UpdatedKeys}, nil
}

func (s Service) EncryptFile(req EncryptRequest) (string, error) {
	if req.InputPath == "" {
		return "", fmt.Errorf("input path is required")
	}
	info, err := safeio.Stat(req.InputPath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("input path %q is a directory", req.InputPath)
	}
	plaintext, err := safeio.ReadFile(req.InputPath)
	if err != nil {
		return "", err
	}
	originalMode := uint32(info.Mode().Perm())

	meta := envelope.Metadata{
		Version:          1,
		Mode:             req.Mode,
		OriginalName:     filepath.Base(req.InputPath),
		OriginalFileMode: &originalMode,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		PayloadEncoding:  "base64",
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
	if err := writeFileSecure(outputPath, encoded, 0o600); err != nil {
		return "", err
	}
	return outputPath, nil
}

func (s Service) Inspect(path string) (envelope.Metadata, error) {
	data, err := safeio.ReadFile(path)
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
	data, err := safeio.ReadFile(req.InputPath)
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
		if meta.KDF.Algorithm != "argon2id" {
			return "", fmt.Errorf("unsupported kdf algorithm %q", meta.KDF.Algorithm)
		}
		salt, err := base64.StdEncoding.DecodeString(meta.KDF.SaltBase64)
		if err != nil {
			return "", fmt.Errorf("decode salt: %w", err)
		}
		if len(payload) < password.NonceSize {
			return "", fmt.Errorf("malformed password payload")
		}
		params := password.Params{
			Salt:        salt,
			Nonce:       append([]byte{}, payload[:password.NonceSize]...),
			MemoryKiB:   meta.KDF.MemoryKiB,
			Iterations:  meta.KDF.Iterations,
			Parallelism: meta.KDF.Parallelism,
			KeyLength:   password.KeySize,
		}
		protected, err = password.Decrypt(payload[password.NonceSize:], req.Passphrase, params)
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
	fileMode := os.FileMode(0o600)
	if meta.OriginalFileMode != nil {
		fileMode = os.FileMode(*meta.OriginalFileMode).Perm()
	}
	if err := writeFileSecure(outputPath, plaintext, fileMode); err != nil {
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
	data, err := safeio.ReadFile(expanded)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && path == config.DefaultKeyFile {
			legacyPath := expandHome(config.LegacyKeyFile)
			legacyData, legacyErr := safeio.ReadFile(legacyPath)
			if legacyErr == nil {
				return string(legacyData), nil
			}
		}
		return "", err
	}
	return string(data), nil
}

func expandHome(path string) string {
	rest, ok := trimHomePrefix(path)
	if !ok {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	rest = strings.ReplaceAll(rest, "\\", string(os.PathSeparator))
	rest = strings.ReplaceAll(rest, "/", string(os.PathSeparator))
	return filepath.Join(home, rest)
}

func writeFileSecure(path string, data []byte, mode os.FileMode) error {
	return safeio.WriteFile(path, data, mode)
}

func trimHomePrefix(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "~/"):
		return path[2:], true
	case strings.HasPrefix(path, "~\\"):
		return path[2:], true
	default:
		return "", false
	}
}

func defaultInlineDecryptOutputPath(inputPath, defaultSuffix string) string {
	if defaultSuffix != "" && strings.HasSuffix(inputPath, defaultSuffix) {
		return strings.TrimSuffix(inputPath, defaultSuffix)
	}
	if strings.HasSuffix(inputPath, ".dpx") {
		return strings.TrimSuffix(inputPath, ".dpx")
	}
	return inputPath + ".dec"
}
