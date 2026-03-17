package envelope

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	ModeAge      = "age"
	ModePassword = "password"

	headerVersionKey       = "DPX-File-Version"
	legacyHeaderVersionKey = "DOPX-File-Version"
)

type Metadata struct {
	Version         int
	Mode            string
	OriginalName    string
	CreatedAt       time.Time
	PayloadEncoding string
	KDF             *KDFParams
}

type KDFParams struct {
	Algorithm   string
	SaltBase64  string
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

func Marshal(meta Metadata, payload []byte) ([]byte, error) {
	if meta.Version <= 0 {
		return nil, errors.New("version is required")
	}
	if meta.Mode == "" {
		return nil, errors.New("mode is required")
	}
	if meta.OriginalName == "" {
		return nil, errors.New("original name is required")
	}
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	if meta.PayloadEncoding == "" {
		meta.PayloadEncoding = "base64"
	}
	if meta.PayloadEncoding != "base64" {
		return nil, fmt.Errorf("unsupported payload encoding %q", meta.PayloadEncoding)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s: %d\n", headerVersionKey, meta.Version)
	fmt.Fprintf(&buf, "Mode: %s\n", meta.Mode)
	fmt.Fprintf(&buf, "Original-Name: %s\n", meta.OriginalName)
	fmt.Fprintf(&buf, "Created-At: %s\n", meta.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "Payload-Encoding: %s\n", meta.PayloadEncoding)
	if meta.KDF != nil {
		fmt.Fprintf(&buf, "KDF-Algorithm: %s\n", meta.KDF.Algorithm)
		fmt.Fprintf(&buf, "KDF-Salt: %s\n", meta.KDF.SaltBase64)
		fmt.Fprintf(&buf, "KDF-Memory-KiB: %d\n", meta.KDF.MemoryKiB)
		fmt.Fprintf(&buf, "KDF-Iterations: %d\n", meta.KDF.Iterations)
		fmt.Fprintf(&buf, "KDF-Parallelism: %d\n", meta.KDF.Parallelism)
	}
	buf.WriteString("\n")
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if _, err := encoder.Write(payload); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')

	return buf.Bytes(), nil
}

func Unmarshal(data []byte) (Metadata, []byte, error) {
	var meta Metadata

	sections := bytes.SplitN(data, []byte("\n\n"), 2)
	if len(sections) != 2 {
		return meta, nil, errors.New("malformed envelope: missing header separator")
	}

	scanner := bufio.NewScanner(bytes.NewReader(sections[0]))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return meta, nil, fmt.Errorf("malformed header line %q", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case headerVersionKey, legacyHeaderVersionKey:
			version, err := strconv.Atoi(value)
			if err != nil {
				return meta, nil, fmt.Errorf("parse version: %w", err)
			}
			meta.Version = version
		case "Mode":
			meta.Mode = value
		case "Original-Name":
			meta.OriginalName = value
		case "Created-At":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return meta, nil, fmt.Errorf("parse created-at: %w", err)
			}
			meta.CreatedAt = ts
		case "Payload-Encoding":
			meta.PayloadEncoding = value
		case "KDF-Algorithm":
			ensureKDF(&meta)
			meta.KDF.Algorithm = value
		case "KDF-Salt":
			ensureKDF(&meta)
			meta.KDF.SaltBase64 = value
		case "KDF-Memory-KiB":
			ensureKDF(&meta)
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return meta, nil, fmt.Errorf("parse kdf memory: %w", err)
			}
			meta.KDF.MemoryKiB = uint32(n)
		case "KDF-Iterations":
			ensureKDF(&meta)
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return meta, nil, fmt.Errorf("parse kdf iterations: %w", err)
			}
			meta.KDF.Iterations = uint32(n)
		case "KDF-Parallelism":
			ensureKDF(&meta)
			n, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return meta, nil, fmt.Errorf("parse kdf parallelism: %w", err)
			}
			meta.KDF.Parallelism = uint8(n)
		}
	}
	if err := scanner.Err(); err != nil {
		return meta, nil, err
	}

	if meta.Version == 0 || meta.Mode == "" || meta.OriginalName == "" {
		return meta, nil, errors.New("malformed envelope: missing required metadata")
	}
	if meta.PayloadEncoding == "" {
		meta.PayloadEncoding = "base64"
	}
	if meta.PayloadEncoding != "base64" {
		return meta, nil, fmt.Errorf("unsupported payload encoding %q", meta.PayloadEncoding)
	}

	payloadText := strings.TrimSpace(string(sections[1]))
	payload, err := base64.StdEncoding.DecodeString(payloadText)
	if err != nil {
		return meta, nil, fmt.Errorf("decode payload: %w", err)
	}
	return meta, payload, nil
}

func ensureKDF(meta *Metadata) {
	if meta.KDF == nil {
		meta.KDF = &KDFParams{}
	}
}
