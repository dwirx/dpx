package tui

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestPromptAgeKeyBlockStopsAtSecretKeyLine(t *testing.T) {
	t.Parallel()

	privateKey := "AGE-SECRET-KEY-1TESTSECRETKEY"
	input := strings.Join([]string{
		"# created: 2026-03-17T18:14:43Z",
		"# public key: age1testrecipient",
		privateKey,
		"/tmp/imported-age-keys.txt",
		"",
	}, "\n")
	reader := bufio.NewReader(strings.NewReader(input))
	stdout := new(bytes.Buffer)

	raw, err := promptAgeKeyBlock(reader, stdout, "Paste key block")
	if err != nil {
		t.Fatalf("promptAgeKeyBlock: %v", err)
	}
	if !strings.Contains(raw, privateKey) {
		t.Fatalf("expected private key in captured block, got %q", raw)
	}
	if strings.Contains(raw, "/tmp/imported-age-keys.txt") {
		t.Fatalf("expected reader to stop before output path, got %q", raw)
	}

	next, err := prompt(reader, stdout, "Output key path: ")
	if err != nil {
		t.Fatalf("prompt output path: %v", err)
	}
	if next != "/tmp/imported-age-keys.txt" {
		t.Fatalf("expected output path to remain unread, got %q", next)
	}
}

func TestPromptAgeKeyBlockSupportsEndTerminator(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"# created: 2026-03-17T18:14:43Z",
		"# public key: age1testrecipient",
		"END",
		"ignored-after-end",
		"",
	}, "\n")
	reader := bufio.NewReader(strings.NewReader(input))
	stdout := new(bytes.Buffer)

	raw, err := promptAgeKeyBlock(reader, stdout, "Paste key block")
	if err != nil {
		t.Fatalf("promptAgeKeyBlock: %v", err)
	}
	if strings.Contains(raw, "END") {
		t.Fatalf("expected END terminator excluded, got %q", raw)
	}

	next, err := prompt(reader, stdout, "Next: ")
	if err != nil {
		t.Fatalf("prompt next: %v", err)
	}
	if next != "ignored-after-end" {
		t.Fatalf("expected data after END to remain unread, got %q", next)
	}
}
