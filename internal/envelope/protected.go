package envelope

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

var ErrMetadataMismatch = errors.New("protected metadata mismatch")

type protectedPayload struct {
	Metadata  Metadata `json:"metadata"`
	Plaintext []byte   `json:"plaintext"`
}

func MarshalProtected(meta Metadata, plaintext []byte) ([]byte, error) {
	payload := protectedPayload{
		Metadata:  normalizedMetadata(meta),
		Plaintext: plaintext,
	}
	return json.Marshal(payload)
}

func UnmarshalProtected(expected Metadata, data []byte) ([]byte, error) {
	var payload protectedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(normalizedMetadata(expected), normalizedMetadata(payload.Metadata)) {
		return nil, ErrMetadataMismatch
	}
	return payload.Plaintext, nil
}

func normalizedMetadata(meta Metadata) Metadata {
	meta.CreatedAt = meta.CreatedAt.UTC().Truncate(time.Second)
	if meta.PayloadEncoding == "" {
		meta.PayloadEncoding = "base64"
	}
	return meta
}
