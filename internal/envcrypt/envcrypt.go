package envcrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/crypto/password"
	"github.com/dwirx/dpx/internal/envelope"
)

const (
	prefixAge   = "ENC[age:"
	prefixPwdV1 = "ENC[pwd:v1:"
	tokenSuffix = "]"
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type EncryptRequest struct {
	Mode         string
	Recipients   []string
	Passphrase   []byte
	SelectedKeys []string
}

type DecryptRequest struct {
	PrivateKey string
	Passphrase []byte
}

type SetRequest struct {
	Key        string
	Value      string
	Encrypt    bool
	Mode       string
	Recipients []string
	Passphrase []byte
}

type UpdateRecipientsRequest struct {
	PrivateKey   string
	Recipients   []string
	SelectedKeys []string
}

type Result struct {
	UpdatedKeys []string
}

type passwordBlobV1 struct {
	Nonce       string `json:"nonce"`
	Salt        string `json:"salt"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	Ciphertext  string `json:"ciphertext"`
}

type lineRecord struct {
	raw       string
	hasAssign bool
	left      string
	key       string
	value     string
}

func Set(content []byte, req SetRequest) ([]byte, Result, error) {
	key := strings.TrimSpace(req.Key)
	if !envKeyPattern.MatchString(key) {
		return nil, Result{}, fmt.Errorf("invalid env key %q", req.Key)
	}
	if req.Encrypt {
		if req.Mode != envelope.ModeAge && req.Mode != envelope.ModePassword {
			return nil, Result{}, fmt.Errorf("unsupported mode %q", req.Mode)
		}
		if req.Mode == envelope.ModeAge && len(req.Recipients) == 0 {
			return nil, Result{}, fmt.Errorf("recipients are required for age mode")
		}
		if req.Mode == envelope.ModePassword && len(req.Passphrase) == 0 {
			return nil, Result{}, fmt.Errorf("passphrase is required for password mode")
		}
	}

	value := req.Value
	if req.Encrypt {
		token, err := encryptValue(req.Value, EncryptRequest{
			Mode:       req.Mode,
			Recipients: req.Recipients,
			Passphrase: req.Passphrase,
		})
		if err != nil {
			return nil, Result{}, err
		}
		value = token
	}

	lines, hadTrailingNewline := parseLines(content)
	updated := false
	for idx, rec := range lines {
		if !rec.hasAssign || rec.key != key {
			continue
		}
		lines[idx].raw = rec.left + "=" + preserveValuePadding(rec.value, value)
		updated = true
		break
	}
	if !updated {
		lines = append(lines, lineRecord{
			raw:       key + "=" + value,
			hasAssign: true,
			left:      key,
			key:       key,
			value:     value,
		})
	}
	return buildContent(lines, hadTrailingNewline), Result{UpdatedKeys: []string{key}}, nil
}

func UpdateAgeRecipients(content []byte, req UpdateRecipientsRequest) ([]byte, Result, error) {
	if strings.TrimSpace(req.PrivateKey) == "" {
		return nil, Result{}, fmt.Errorf("private key is required")
	}
	if len(req.Recipients) == 0 {
		return nil, Result{}, fmt.Errorf("recipients are required")
	}

	selected := make(map[string]struct{}, len(req.SelectedKeys))
	for _, key := range req.SelectedKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed != "" {
			selected[trimmed] = struct{}{}
		}
	}
	allSelected := len(selected) == 0

	lines, hadTrailingNewline := parseLines(content)
	updatedSet := make(map[string]struct{})
	for idx, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		if !allSelected {
			if _, ok := selected[rec.key]; !ok {
				continue
			}
		}
		mode, payload, ok := parseToken(rec.value)
		if !ok || mode != envelope.ModeAge {
			continue
		}
		plain, err := decryptValue(mode, payload, DecryptRequest{PrivateKey: req.PrivateKey})
		if err != nil {
			return nil, Result{}, fmt.Errorf("decrypt %s: %w", rec.key, err)
		}
		token, err := encryptValue(plain, EncryptRequest{
			Mode:       envelope.ModeAge,
			Recipients: req.Recipients,
		})
		if err != nil {
			return nil, Result{}, fmt.Errorf("encrypt %s: %w", rec.key, err)
		}
		lines[idx].raw = rec.left + "=" + preserveValuePadding(rec.value, token)
		updatedSet[rec.key] = struct{}{}
	}

	updatedKeys := mapKeysSorted(updatedSet)
	if len(updatedKeys) == 0 {
		return nil, Result{}, fmt.Errorf("no age-encrypted keys found")
	}
	return buildContent(lines, hadTrailingNewline), Result{UpdatedKeys: updatedKeys}, nil
}

func Encrypt(content []byte, req EncryptRequest) ([]byte, Result, error) {
	if req.Mode != envelope.ModeAge && req.Mode != envelope.ModePassword {
		return nil, Result{}, fmt.Errorf("unsupported mode %q", req.Mode)
	}
	if req.Mode == envelope.ModeAge && len(req.Recipients) == 0 {
		return nil, Result{}, fmt.Errorf("recipients are required for age mode")
	}
	if req.Mode == envelope.ModePassword && len(req.Passphrase) == 0 {
		return nil, Result{}, fmt.Errorf("passphrase is required for password mode")
	}

	lines, hadTrailingNewline := parseLines(content)
	selected := make(map[string]struct{}, len(req.SelectedKeys))
	for _, key := range req.SelectedKeys {
		trimmed := strings.TrimSpace(key)
		if trimmed != "" {
			selected[trimmed] = struct{}{}
		}
	}
	allSelected := len(selected) == 0

	updatedSet := make(map[string]struct{})
	for idx, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		if !allSelected {
			if _, ok := selected[rec.key]; !ok {
				continue
			}
		}
		if _, _, ok := parseToken(rec.value); ok {
			continue
		}

		token, err := encryptValue(rec.value, req)
		if err != nil {
			return nil, Result{}, err
		}
		lines[idx].raw = rec.left + "=" + preserveValuePadding(rec.value, token)
		updatedSet[rec.key] = struct{}{}
	}

	updatedKeys := mapKeysSorted(updatedSet)
	if len(updatedKeys) == 0 {
		return nil, Result{}, fmt.Errorf("no matching keys were encrypted")
	}
	return buildContent(lines, hadTrailingNewline), Result{UpdatedKeys: updatedKeys}, nil
}

func Decrypt(content []byte, req DecryptRequest) ([]byte, Result, error) {
	lines, hadTrailingNewline := parseLines(content)
	updatedSet := make(map[string]struct{})

	for idx, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		mode, payload, ok := parseToken(rec.value)
		if !ok {
			continue
		}
		plain, err := decryptValue(mode, payload, req)
		if err != nil {
			return nil, Result{}, fmt.Errorf("decrypt %s: %w", rec.key, err)
		}
		lines[idx].raw = rec.left + "=" + preserveValuePadding(rec.value, plain)
		updatedSet[rec.key] = struct{}{}
	}

	updatedKeys := mapKeysSorted(updatedSet)
	if len(updatedKeys) == 0 {
		return nil, Result{}, fmt.Errorf("no encrypted keys found")
	}
	return buildContent(lines, hadTrailingNewline), Result{UpdatedKeys: updatedKeys}, nil
}

func ListEncryptableKeys(content []byte) []string {
	lines, _ := parseLines(content)
	unique := make(map[string]struct{})
	for _, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		if _, _, ok := parseToken(rec.value); ok {
			continue
		}
		unique[rec.key] = struct{}{}
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func DetectModes(content []byte) (bool, bool) {
	lines, _ := parseLines(content)
	hasAge := false
	hasPassword := false
	for _, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		mode, _, ok := parseToken(rec.value)
		if !ok {
			continue
		}
		switch mode {
		case envelope.ModeAge:
			hasAge = true
		case envelope.ModePassword:
			hasPassword = true
		}
	}
	return hasAge, hasPassword
}

func encryptValue(value string, req EncryptRequest) (string, error) {
	switch req.Mode {
	case envelope.ModeAge:
		ciphertext, err := agex.Encrypt([]byte(value), req.Recipients)
		if err != nil {
			return "", err
		}
		return prefixAge + base64.RawURLEncoding.EncodeToString(ciphertext) + tokenSuffix, nil
	case envelope.ModePassword:
		params, err := password.NewParams()
		if err != nil {
			return "", err
		}
		sealed, err := password.EncryptWithParams([]byte(value), req.Passphrase, params)
		if err != nil {
			return "", err
		}
		blob := passwordBlobV1{
			Nonce:       base64.RawURLEncoding.EncodeToString(params.Nonce),
			Salt:        base64.RawURLEncoding.EncodeToString(params.Salt),
			MemoryKiB:   params.MemoryKiB,
			Iterations:  params.Iterations,
			Parallelism: params.Parallelism,
			Ciphertext:  base64.RawURLEncoding.EncodeToString(sealed),
		}
		encoded, err := json.Marshal(blob)
		if err != nil {
			return "", err
		}
		return prefixPwdV1 + base64.RawURLEncoding.EncodeToString(encoded) + tokenSuffix, nil
	default:
		return "", fmt.Errorf("unsupported mode %q", req.Mode)
	}
}

func decryptValue(mode, payload string, req DecryptRequest) (string, error) {
	switch mode {
	case envelope.ModeAge:
		if strings.TrimSpace(req.PrivateKey) == "" {
			return "", fmt.Errorf("private key is required for age token")
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("decode age payload: %w", err)
		}
		plaintext, err := agex.Decrypt(ciphertext, req.PrivateKey)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	case envelope.ModePassword:
		if len(req.Passphrase) == 0 {
			return "", fmt.Errorf("passphrase is required for password token")
		}
		blobJSON, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("decode password payload: %w", err)
		}
		var blob passwordBlobV1
		if err := json.Unmarshal(blobJSON, &blob); err != nil {
			return "", fmt.Errorf("parse password payload: %w", err)
		}
		nonce, err := base64.RawURLEncoding.DecodeString(blob.Nonce)
		if err != nil {
			return "", fmt.Errorf("decode nonce: %w", err)
		}
		salt, err := base64.RawURLEncoding.DecodeString(blob.Salt)
		if err != nil {
			return "", fmt.Errorf("decode salt: %w", err)
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(blob.Ciphertext)
		if err != nil {
			return "", fmt.Errorf("decode ciphertext: %w", err)
		}
		params := password.Params{
			Salt:        salt,
			Nonce:       nonce,
			MemoryKiB:   blob.MemoryKiB,
			Iterations:  blob.Iterations,
			Parallelism: blob.Parallelism,
			KeyLength:   password.KeySize,
		}
		plaintext, err := password.Decrypt(ciphertext, req.Passphrase, params)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	default:
		return "", fmt.Errorf("unsupported token mode %q", mode)
	}
}

func parseToken(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, prefixAge) && strings.HasSuffix(trimmed, tokenSuffix) {
		payload := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefixAge), tokenSuffix)
		if payload == "" {
			return "", "", false
		}
		return envelope.ModeAge, payload, true
	}
	if strings.HasPrefix(trimmed, prefixPwdV1) && strings.HasSuffix(trimmed, tokenSuffix) {
		payload := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefixPwdV1), tokenSuffix)
		if payload == "" {
			return "", "", false
		}
		return envelope.ModePassword, payload, true
	}
	return "", "", false
}

func parseLines(content []byte) ([]lineRecord, bool) {
	text := string(content)
	hadTrailingNewline := strings.HasSuffix(text, "\n")
	parts := strings.Split(text, "\n")
	if hadTrailingNewline {
		parts = parts[:len(parts)-1]
	}
	lines := make([]lineRecord, 0, len(parts))
	for _, raw := range parts {
		left, key, value, ok := parseAssignment(raw)
		lines = append(lines, lineRecord{
			raw:       raw,
			hasAssign: ok,
			left:      left,
			key:       key,
			value:     value,
		})
	}
	return lines, hadTrailingNewline
}

func buildContent(lines []lineRecord, hadTrailingNewline bool) []byte {
	raw := make([]string, 0, len(lines))
	for _, rec := range lines {
		raw = append(raw, rec.raw)
	}
	content := strings.Join(raw, "\n")
	if hadTrailingNewline {
		content += "\n"
	}
	return []byte(content)
}

func parseAssignment(line string) (string, string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", "", false
	}
	idx := strings.Index(line, "=")
	if idx <= 0 {
		return "", "", "", false
	}
	left := line[:idx]
	value := line[idx+1:]
	keyPart := strings.TrimSpace(left)
	if strings.HasPrefix(keyPart, "export ") {
		keyPart = strings.TrimSpace(strings.TrimPrefix(keyPart, "export "))
	}
	if !envKeyPattern.MatchString(keyPart) {
		return "", "", "", false
	}
	return left, keyPart, value, true
}

func preserveValuePadding(original, replaced string) string {
	lead := len(original) - len(strings.TrimLeft(original, " \t"))
	trail := len(original) - len(strings.TrimRight(original, " \t"))
	if lead+trail > len(original) {
		return replaced
	}
	return original[:lead] + replaced + original[len(original)-trail:]
}

func mapKeysSorted(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
