package tui

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

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

	if got.stage != stageEncryptFile {
		t.Fatalf("expected encrypt file stage, got %v", got.stage)
	}
	if !containsOption(got.options, manualEncryptPathOption) {
		t.Fatalf("expected manual option in stage options, got %#v", got.options)
	}
}

func TestModelEncryptWithCandidatesHasManualPathOption(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)

	if menu.stage != stageEncryptFile {
		t.Fatalf("expected encrypt file selection stage, got %v", menu.stage)
	}
	if len(menu.options) < 2 {
		t.Fatalf("expected candidate + manual option, got %#v", menu.options)
	}
	manualIdx := optionIndex(menu.options, manualEncryptPathOption)
	if manualIdx < 0 {
		t.Fatalf("expected manual option, got %#v", menu.options)
	}

	menu.selection = manualIdx
	updated, _ = menu.submitSelection()
	got := updated.(Model)
	if got.stage != stageEncryptManualPath {
		t.Fatalf("expected manual path input stage, got %v", got.stage)
	}
	if got.input.Prompt != "File to encrypt: " {
		t.Fatalf("unexpected prompt: %q", got.input.Prompt)
	}
}

func TestModelEncryptPasswordRequiresConfirmation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	menu.selection = 1
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	if menu.stage != stageEncryptPassword {
		t.Fatalf("expected password stage, got %v", menu.stage)
	}

	menu.input.SetValue("secret-123")
	updated, _ = menu.submitInput()
	menu = updated.(Model)
	if menu.stage != stageEncryptPasswordConfirm {
		t.Fatalf("expected password confirm stage, got %v", menu.stage)
	}

	menu.input.SetValue("wrong-secret")
	updated, _ = menu.submitInput()
	menu = updated.(Model)
	if menu.stage != stageEncryptPassword {
		t.Fatalf("expected password stage after mismatch, got %v", menu.stage)
	}

	menu.input.SetValue("secret-123")
	updated, _ = menu.submitInput()
	menu = updated.(Model)
	if menu.stage != stageEncryptPasswordConfirm {
		t.Fatalf("expected password confirm stage, got %v", menu.stage)
	}
	menu.input.SetValue("secret-123")
	updated, _ = menu.submitInput()
	menu = updated.(Model)
	if menu.stage != stageEncryptOutput {
		t.Fatalf("expected encrypt output stage, got %v", menu.stage)
	}
}

func TestModelEscBackReturnsToPreviousStage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	if menu.stage != stageEncryptFile {
		t.Fatalf("expected encrypt file stage, got %v", menu.stage)
	}

	backed, _ := menu.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := backed.(Model)
	if got.stage != stageAction {
		t.Fatalf("expected back to action stage, got %v", got.stage)
	}
}

func TestModelCtrlVTogglePasswordVisibility(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	menu.selection = 1
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	if menu.stage != stageEncryptPassword {
		t.Fatalf("expected password stage, got %v", menu.stage)
	}
	if menu.input.EchoMode != textinput.EchoPassword {
		t.Fatalf("expected password echo mode, got %v", menu.input.EchoMode)
	}

	toggled, _ := menu.Update(tea.KeyMsg{Type: tea.KeyCtrlV})
	got := toggled.(Model)
	if got.input.EchoMode != textinput.EchoNormal {
		t.Fatalf("expected normal echo mode after toggle, got %v", got.input.EchoMode)
	}

	toggled, _ = got.Update(tea.KeyMsg{Type: tea.KeyCtrlV})
	got = toggled.(Model)
	if got.input.EchoMode != textinput.EchoPassword {
		t.Fatalf("expected password echo mode after second toggle, got %v", got.input.EchoMode)
	}
}

func TestModelEncryptSuggestionsIncludeCommonFileTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{".env", "notes.txt", "README.md", "script.js", "payload.bin", "app.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	if menu.stage != stageEncryptFile {
		t.Fatalf("expected encrypt file stage, got %v", menu.stage)
	}
	if menu.title != "Select a file to encrypt (all files mode)" {
		t.Fatalf("unexpected title: %q", menu.title)
	}

	options := strings.Join(menu.options, "\n")
	for _, name := range []string{".env", "notes.txt", "README.md", "script.js", "payload.bin", "app.exe"} {
		if !strings.Contains(options, name) {
			t.Fatalf("expected %s in options, got %#v", name, menu.options)
		}
	}
}

func TestModelEncryptSearchFiltersCandidates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{".env", "notes.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	searchIdx := optionIndex(menu.options, searchEncryptPathOption)
	if searchIdx < 0 {
		t.Fatalf("expected search option, got %#v", menu.options)
	}
	menu.selection = searchIdx
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	if menu.stage != stageEncryptSearchQuery {
		t.Fatalf("expected search query stage, got %v", menu.stage)
	}

	menu.input.SetValue("readme")
	updated, _ = menu.submitInput()
	menu = updated.(Model)
	if menu.stage != stageEncryptFile {
		t.Fatalf("expected back to encrypt file stage, got %v", menu.stage)
	}
	if !strings.Contains(strings.Join(menu.options, "\n"), "README.md") {
		t.Fatalf("expected filtered option to include README.md, got %#v", menu.options)
	}
	if strings.Contains(strings.Join(menu.options, "\n"), "notes.txt") {
		t.Fatalf("expected notes.txt to be filtered out, got %#v", menu.options)
	}
}

func TestModelEncryptSearchRealtimeSuggestions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{".env", "notes.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	searchIdx := optionIndex(menu.options, searchEncryptPathOption)
	if searchIdx < 0 {
		t.Fatalf("expected search option, got %#v", menu.options)
	}
	menu.selection = searchIdx
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	if menu.stage != stageEncryptSearchQuery {
		t.Fatalf("expected search query stage, got %v", menu.stage)
	}

	menu.input.SetValue("readme.md")
	menu.syncEncryptSearchSuggestions()

	if menu.stage != stageEncryptSearchQuery {
		t.Fatalf("expected to stay in search stage during typing, got %v", menu.stage)
	}
	if len(menu.encryptShown) != 1 {
		t.Fatalf("expected one live suggestion, got %#v", menu.encryptShown)
	}
	if !strings.Contains(menu.encryptShown[0], "README.md") {
		t.Fatalf("expected README.md suggestion, got %#v", menu.encryptShown)
	}
	if !strings.Contains(menu.help, "suggestion") {
		t.Fatalf("expected suggestion help message, got %q", menu.help)
	}

	view := menu.View()
	if !strings.Contains(view, "Suggestions: 1") {
		t.Fatalf("expected suggestions counter in view, got %q", view)
	}
	if !strings.Contains(view, "README.md") {
		t.Fatalf("expected README.md in suggestions view, got %q", view)
	}
}

func TestModelEncryptCanSwitchScopeToEnvMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{".env", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	model, err := NewModel(app.New(config.Default()), config.Default(), dir, nil, io.Discard)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}

	updated, _ := model.submitSelection()
	menu := updated.(Model)
	switchIdx := optionIndex(menu.options, encryptScopeSwitchOption(encryptScopeAny))
	if switchIdx < 0 {
		t.Fatalf("expected scope switch option, got %#v", menu.options)
	}
	menu.selection = switchIdx
	updated, _ = menu.submitSelection()
	menu = updated.(Model)
	if menu.title != "Select a file to encrypt (.env mode)" {
		t.Fatalf("expected env mode title, got %q", menu.title)
	}
	options := strings.Join(menu.options, "\n")
	if !strings.Contains(options, ".env") {
		t.Fatalf("expected .env option, got %#v", menu.options)
	}
	if strings.Contains(options, "notes.txt") {
		t.Fatalf("expected notes.txt excluded in env mode, got %#v", menu.options)
	}
}

func containsOption(options []string, target string) bool {
	return optionIndex(options, target) >= 0
}

func optionIndex(options []string, target string) int {
	for i, option := range options {
		if option == target {
			return i
		}
	}
	return -1
}

func TestSplitSearchMatch(t *testing.T) {
	t.Parallel()

	prefix, match, suffix, ok := splitSearchMatch("/tmp/README.md", "read")
	if !ok {
		t.Fatalf("expected match")
	}
	if prefix != "/tmp/" {
		t.Fatalf("unexpected prefix: %q", prefix)
	}
	if match != "READ" {
		t.Fatalf("unexpected match segment: %q", match)
	}
	if suffix != "ME.md" {
		t.Fatalf("unexpected suffix: %q", suffix)
	}

	_, _, _, ok = splitSearchMatch("/tmp/notes.txt", "read")
	if ok {
		t.Fatalf("did not expect match")
	}
}
