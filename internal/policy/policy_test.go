package policy

import (
	"strings"
	"testing"
)

func TestCheckDetectsPlaintextSecretsInEnv(t *testing.T) {
	t.Parallel()

	input := []byte("API_KEY=plain\nDEBUG=true\nJWT_SECRET=ENC[pwd:v1:abc]\n")
	report := Check("app.env", input)

	if report.Format != "env" {
		t.Fatalf("expected env format, got %q", report.Format)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Key != "API_KEY" {
		t.Fatalf("expected API_KEY finding, got %#v", report.Findings[0])
	}
}

func TestCheckDetectsPlaintextSecretsInJSON(t *testing.T) {
	t.Parallel()

	input := []byte(`{"api_key":"plain","debug":"true","nested":{"jwt_secret":"ENC[pwd:v1:ok]"}}`)
	report := Check("app.json", input)

	if report.Format != "json" {
		t.Fatalf("expected json format, got %q", report.Format)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Key != "api_key" {
		t.Fatalf("expected api_key finding, got %#v", report.Findings[0])
	}
}

func TestCheckDetectsPlaintextSecretsInYAMLLike(t *testing.T) {
	t.Parallel()

	input := []byte("api_key: plain\nnested:\n  jwt_secret: ENC[pwd:v1:ok]\n")
	report := Check("app.yaml", input)

	if report.Format != "yaml" {
		t.Fatalf("expected yaml format, got %q", report.Format)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if !strings.EqualFold(report.Findings[0].Key, "api_key") {
		t.Fatalf("expected api_key finding, got %#v", report.Findings[0])
	}
}

func TestCheckSkipsDPXEnvelope(t *testing.T) {
	t.Parallel()

	input := []byte("DPX-File-Version: 1\nMode: password\n\nAAAA\n")
	report := Check("secret.env.dpx", input)

	if report.SkipReason == "" {
		t.Fatalf("expected skip reason for dpx envelope")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(report.Findings))
	}
}

func TestCheckSkipsBinary(t *testing.T) {
	t.Parallel()

	input := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	report := Check("data.bin", input)

	if report.SkipReason == "" {
		t.Fatalf("expected skip reason for binary")
	}
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(report.Findings))
	}
}
