package tui

import (
	"io"
	"testing"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
)

func TestModelEncryptWithoutCandidatesPromptsManualPath(t *testing.T) {
	t.Parallel()

	model, err := NewModel(app.New(config.Default()), config.Default(), t.TempDir(), nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	got := updated.(Model)

	if got.stage != stageEncryptManualPath {
		t.Fatalf("expected manual encrypt path stage, got %v", got.stage)
	}
	if got.input.Prompt != "File to encrypt: " {
		t.Fatalf("unexpected prompt: %q", got.input.Prompt)
	}
}
