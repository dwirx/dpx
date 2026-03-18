package envcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
	prefixV2    = "ENC[v2:"
	prefixAge   = "ENC[age:"
	prefixPwdV1 = "ENC[pwd:v1:"
	tokenSuffix = "]"

	tokenModeAge byte = 1
	tokenModePwd byte = 2
	maxPadBytes       = 24
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type EncryptRequest struct {
	Mode         string
	Recipients   []string
	Passphrase   []byte
	SelectedKeys []string
	KDFProfile   string
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
	KDFProfile string
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

type tokenData struct {
	mode    string
	payload []byte
	legacy  bool
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
			KDFProfile: req.KDFProfile,
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
		token, ok := parseToken(rec.value)
		if !ok || token.mode != envelope.ModeAge {
			continue
		}
		plain, err := decryptValue(token, DecryptRequest{PrivateKey: req.PrivateKey})
		if err != nil {
			return nil, Result{}, fmt.Errorf("decrypt %s: %w", rec.key, err)
		}
		reEncryptedToken, err := encryptValue(plain, EncryptRequest{
			Mode:       envelope.ModeAge,
			Recipients: req.Recipients,
		})
		if err != nil {
			return nil, Result{}, fmt.Errorf("encrypt %s: %w", rec.key, err)
		}
		lines[idx].raw = rec.left + "=" + preserveValuePadding(rec.value, reEncryptedToken)
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
		if _, ok := parseToken(rec.value); ok {
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
		token, ok := parseToken(rec.value)
		if !ok {
			continue
		}
		plain, err := decryptValue(token, req)
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
		if _, ok := parseToken(rec.value); ok {
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

func ListAgeEncryptedKeys(content []byte) []string {
	lines, _ := parseLines(content)
	unique := make(map[string]struct{})
	for _, rec := range lines {
		if !rec.hasAssign {
			continue
		}
		token, ok := parseToken(rec.value)
		if !ok || token.mode != envelope.ModeAge {
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
		token, ok := parseToken(rec.value)
		if !ok {
			continue
		}
		switch token.mode {
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
		return encodeV2Token(tokenModeAge, ciphertext)
	case envelope.ModePassword:
		params, err := password.NewParamsForProfile(req.KDFProfile)
		if err != nil {
			return "", err
		}
		sealed, err := password.EncryptWithParams([]byte(value), req.Passphrase, params)
		if err != nil {
			return "", err
		}
		encoded, err := encodePasswordBlobV2(params, sealed)
		if err != nil {
			return "", err
		}
		return encodeV2Token(tokenModePwd, encoded)
	default:
		return "", fmt.Errorf("unsupported mode %q", req.Mode)
	}
}

func decryptValue(token tokenData, req DecryptRequest) (string, error) {
	if token.legacy {
		return decryptLegacyToken(token, req)
	}
	switch token.mode {
	case envelope.ModeAge:
		if strings.TrimSpace(req.PrivateKey) == "" {
			return "", fmt.Errorf("private key is required for age token")
		}
		plaintext, err := agex.Decrypt(token.payload, req.PrivateKey)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	case envelope.ModePassword:
		if len(req.Passphrase) == 0 {
			return "", fmt.Errorf("passphrase is required for password token")
		}
		params, ciphertext, err := decodePasswordBlobV2(token.payload)
		if err != nil {
			return "", err
		}
		plaintext, err := password.Decrypt(ciphertext, req.Passphrase, params)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	default:
		return "", fmt.Errorf("unsupported token mode %q", token.mode)
	}
}

func parseToken(value string) (tokenData, bool) {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, prefixV2) && strings.HasSuffix(trimmed, tokenSuffix) {
		payloadText := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefixV2), tokenSuffix)
		if payloadText == "" {
			return tokenData{}, false
		}
		raw, err := base64.RawURLEncoding.DecodeString(payloadText)
		if err != nil {
			return tokenData{}, false
		}
		if len(raw) < 3 {
			return tokenData{}, false
		}
		modeByte := raw[0]
		padLen := int(raw[1])
		if len(raw) < 2+padLen+1 {
			return tokenData{}, false
		}
		body := raw[2+padLen:]
		switch modeByte {
		case tokenModeAge:
			return tokenData{mode: envelope.ModeAge, payload: body, legacy: false}, true
		case tokenModePwd:
			return tokenData{mode: envelope.ModePassword, payload: body, legacy: false}, true
		default:
			return tokenData{}, false
		}
	}
	if strings.HasPrefix(trimmed, prefixAge) && strings.HasSuffix(trimmed, tokenSuffix) {
		payload := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefixAge), tokenSuffix)
		if payload == "" {
			return tokenData{}, false
		}
		return tokenData{mode: envelope.ModeAge, payload: []byte(payload), legacy: true}, true
	}
	if strings.HasPrefix(trimmed, prefixPwdV1) && strings.HasSuffix(trimmed, tokenSuffix) {
		payload := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefixPwdV1), tokenSuffix)
		if payload == "" {
			return tokenData{}, false
		}
		return tokenData{mode: envelope.ModePassword, payload: []byte(payload), legacy: true}, true
	}
	return tokenData{}, false
}

func decodePasswordBlobV2(payload []byte) (password.Params, []byte, error) {
	if len(payload) < 11 {
		return password.Params{}, nil, fmt.Errorf("malformed password payload")
	}
	memory := binary.BigEndian.Uint32(payload[0:4])
	iterations := binary.BigEndian.Uint32(payload[4:8])
	parallelism := payload[8]
	saltLen := int(payload[9])
	nonceLen := int(payload[10])
	if saltLen <= 0 || nonceLen <= 0 {
		return password.Params{}, nil, fmt.Errorf("malformed password payload")
	}
	headerLen := 11 + saltLen + nonceLen
	if len(payload) <= headerLen {
		return password.Params{}, nil, fmt.Errorf("malformed password payload")
	}
	salt := append([]byte{}, payload[11:11+saltLen]...)
	nonce := append([]byte{}, payload[11+saltLen:headerLen]...)
	ciphertext := append([]byte{}, payload[headerLen:]...)
	params := password.Params{
		Salt:        salt,
		Nonce:       nonce,
		MemoryKiB:   memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		KeyLength:   password.KeySize,
	}
	return params, ciphertext, nil
}

func encodePasswordBlobV2(params password.Params, ciphertext []byte) ([]byte, error) {
	if err := password.ValidateParams(params); err != nil {
		return nil, err
	}
	if len(params.Salt) > 255 {
		return nil, fmt.Errorf("salt too long")
	}
	if len(params.Nonce) > 255 {
		return nil, fmt.Errorf("nonce too long")
	}
	out := make([]byte, 11+len(params.Salt)+len(params.Nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(out[0:4], params.MemoryKiB)
	binary.BigEndian.PutUint32(out[4:8], params.Iterations)
	out[8] = params.Parallelism
	out[9] = byte(len(params.Salt))
	out[10] = byte(len(params.Nonce))
	offset := 11
	copy(out[offset:offset+len(params.Salt)], params.Salt)
	offset += len(params.Salt)
	copy(out[offset:offset+len(params.Nonce)], params.Nonce)
	offset += len(params.Nonce)
	copy(out[offset:], ciphertext)
	return out, nil
}

func encodeV2Token(mode byte, payload []byte) (string, error) {
	padLenRaw := make([]byte, 1)
	if _, err := rand.Read(padLenRaw); err != nil {
		return "", fmt.Errorf("read token pad size: %w", err)
	}
	padLen := int(padLenRaw[0] % byte(maxPadBytes+1))
	pad := make([]byte, padLen)
	if _, err := rand.Read(pad); err != nil {
		return "", fmt.Errorf("read token pad: %w", err)
	}
	raw := make([]byte, 0, 2+padLen+len(payload))
	raw = append(raw, mode, byte(padLen))
	raw = append(raw, pad...)
	raw = append(raw, payload...)
	return prefixV2 + base64.RawURLEncoding.EncodeToString(raw) + tokenSuffix, nil
}

func decryptLegacyToken(token tokenData, req DecryptRequest) (string, error) {
	payload := string(token.payload)
	switch token.mode {
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
		return "", fmt.Errorf("unsupported legacy token mode %q", token.mode)
	}
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
