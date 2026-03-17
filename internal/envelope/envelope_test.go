package envelope_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/dwirx/dpx/internal/envelope"
)

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()

	meta := envelope.Metadata{
		Version:      1,
		Mode:         envelope.ModePassword,
		OriginalName: ".env",
		OriginalFileMode: func() *uint32 {
			mode := uint32(0o640)
			return &mode
		}(),
		CreatedAt:       time.Date(2026, 3, 17, 10, 11, 12, 0, time.UTC),
		PayloadEncoding: "base64",
		KDF: &envelope.KDFParams{
			Algorithm:   "argon2id",
			SaltBase64:  "YWJjMTIz",
			MemoryKiB:   65536,
			Iterations:  3,
			Parallelism: 2,
		},
	}

	payload := []byte("ciphertext-payload")

	encoded, err := envelope.Marshal(meta, payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(encoded, []byte("DPX-File-Version: 1")) {
		t.Fatalf("expected dpx header, got %q", encoded)
	}

	decodedMeta, decodedPayload, err := envelope.Unmarshal(encoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decodedMeta.Mode != meta.Mode {
		t.Fatalf("mode mismatch: got %q want %q", decodedMeta.Mode, meta.Mode)
	}
	if decodedMeta.OriginalName != meta.OriginalName {
		t.Fatalf("original name mismatch: got %q want %q", decodedMeta.OriginalName, meta.OriginalName)
	}
	if decodedMeta.OriginalFileMode == nil || *decodedMeta.OriginalFileMode != 0o640 {
		t.Fatalf("original mode mismatch: got %#v", decodedMeta.OriginalFileMode)
	}
	if decodedMeta.KDF == nil || decodedMeta.KDF.Algorithm != "argon2id" {
		t.Fatalf("expected KDF metadata to survive roundtrip")
	}
	if !bytes.Equal(decodedPayload, payload) {
		t.Fatalf("payload mismatch: got %q want %q", decodedPayload, payload)
	}
}

func TestUnmarshalRejectsMalformedEnvelope(t *testing.T) {
	t.Parallel()

	_, _, err := envelope.Unmarshal([]byte("DOPX-File-Version: 1\nMode: password\n"))
	if err == nil {
		t.Fatal("expected malformed envelope to fail")
	}
}

func TestUnmarshalAcceptsLegacyHeader(t *testing.T) {
	t.Parallel()

	data := []byte("DOPX-File-Version: 1\nMode: password\nOriginal-Name: .env\nCreated-At: 2026-03-17T10:11:12Z\nPayload-Encoding: base64\n\nY2lwaGVy\n")

	meta, payload, err := envelope.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if meta.Version != 1 || meta.OriginalName != ".env" {
		t.Fatalf("legacy metadata mismatch: %#v", meta)
	}
	if !bytes.Equal(payload, []byte("cipher")) {
		t.Fatalf("legacy payload mismatch: %q", payload)
	}
}

func TestMarshalRejectsHeaderInjectionInOriginalName(t *testing.T) {
	t.Parallel()

	meta := envelope.Metadata{
		Version:         1,
		Mode:            envelope.ModePassword,
		OriginalName:    "notes\nKDF-Iterations: 1",
		CreatedAt:       time.Now().UTC(),
		PayloadEncoding: "base64",
	}

	if _, err := envelope.Marshal(meta, []byte("ciphertext")); err == nil {
		t.Fatal("expected marshal to reject header injection")
	}
}
