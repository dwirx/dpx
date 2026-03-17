package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/discovery"
	"github.com/dwirx/dpx/internal/envelope"
)

type stage int

const (
	stageAction stage = iota
	stageAutoPath
	stageEncryptFile
	stageEncryptManualPath
	stageEncryptMode
	stageEncryptPassword
	stageEncryptRecipients
	stageEncryptOutput
	stageDecryptFile
	stageDecryptManualPath
	stageDecryptPassword
	stageDecryptOutput
	stageInspectFile
	stageInspectManualPath
	stageResult
)

type Model struct {
	svc         app.Service
	cfg         config.Config
	cwd         string
	stdin       io.Reader
	stdout      io.Writer
	interactive bool

	stage     stage
	title     string
	help      string
	options   []string
	selection int
	input     textinput.Model
	result    string
	err       error

	encryptReq  app.EncryptRequest
	decryptReq  app.DecryptRequest
	decryptMeta envelope.Metadata
}

func Run(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) error {
	model, err := NewModel(svc, cfg, cwd, stdin, stdout)
	if err != nil {
		return err
	}
	options := []tea.ProgramOption{tea.WithInput(stdin), tea.WithOutput(stdout)}
	if file, ok := stdout.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		options = append(options, tea.WithAltScreen())
	}
	final, err := tea.NewProgram(model, options...).Run()
	if err != nil {
		return err
	}
	return final.(Model).err
}

func NewModel(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) (Model, error) {
	interactive := false
	if file, ok := stdout.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		interactive = true
	}
	m := Model{svc: svc, cfg: cfg, cwd: cwd, stdin: stdin, stdout: stdout, interactive: interactive}
	m.setMenu(stageAction, "Choose an action", []string{"Encrypt", "Decrypt", "Inspect", "Auto"})
	return m, nil
}

func (m Model) Init() tea.Cmd { return textinput.Blink }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
		if m.stage == stageResult {
			if msg.String() == "enter" || msg.String() == "esc" {
				return m, tea.Quit
			}
			return m, nil
		}
		if m.isInputStage() {
			return m.updateInput(msg)
		}
		return m.updateMenu(msg)
	}
	return m, nil
}

func (m Model) View() string {
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	subtitleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	boxStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Width(76)

	var body strings.Builder
	body.WriteString(titleStyle.Render("DPX TUI"))
	body.WriteString("\n")
	body.WriteString(helpStyle.Render("Full-screen secrets workflow for encrypt, decrypt, and inspect"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render(m.title))
	body.WriteString("\n\n")

	if m.isInputStage() {
		body.WriteString(m.input.View())
		body.WriteString("\n")
	} else if m.stage == stageResult {
		body.WriteString(m.result)
		body.WriteString("\n")
	} else {
		for i, option := range m.options {
			line := fmt.Sprintf("  %d. %s", i+1, option)
			if i == m.selection {
				body.WriteString(selectedStyle.Render("> " + line))
			} else {
				body.WriteString(line)
			}
			body.WriteString("\n")
		}
	}

	body.WriteString("\n")
	body.WriteString(helpStyle.Render(m.help))
	return boxStyle.Render(body.String())
}

func (m Model) isInputStage() bool {
	switch m.stage {
	case stageAutoPath,
		stageEncryptManualPath,
		stageEncryptPassword,
		stageEncryptRecipients,
		stageEncryptOutput,
		stageDecryptManualPath,
		stageDecryptPassword,
		stageDecryptOutput,
		stageInspectManualPath:
		return true
	default:
		return false
	}
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.selection > 0 {
			m.selection--
		}
		return m, nil
	case "down", "j":
		if m.selection < len(m.options)-1 {
			m.selection++
		}
		return m, nil
	case "enter":
		return m.submitSelection()
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(msg.Runes[0] - '1')
		if idx >= 0 && idx < len(m.options) {
			m.selection = idx
		}
		return m, nil
	default:
		return m, nil
	}
}

func (m Model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "enter" {
		return m.submitInput()
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) submitSelection() (tea.Model, tea.Cmd) {
	if len(m.options) == 0 {
		m.err = fmt.Errorf("no options available")
		return m, tea.Quit
	}
	selected := m.options[m.selection]
	switch m.stage {
	case stageAction:
		switch selected {
		case "Encrypt":
			candidates, err := m.svc.Discover(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			if len(candidates) == 0 {
				m.setInput(stageEncryptManualPath, "File to encrypt", "", false)
				return m, nil
			}
			m.setMenu(stageEncryptFile, "Select a file to encrypt", candidateLabels(candidates))
		case "Decrypt":
			files, err := findEncryptedFiles(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			if len(files) == 0 {
				m.setInput(stageDecryptManualPath, "File to decrypt (.dpx)", "", false)
				return m, nil
			}
			m.setMenu(stageDecryptFile, "Select a file to decrypt", files)
		case "Inspect":
			files, err := findEncryptedFiles(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			if len(files) == 0 {
				m.setInput(stageInspectManualPath, "File to inspect (.dpx)", "", false)
				return m, nil
			}
			m.setMenu(stageInspectFile, "Select a file to inspect", files)
		case "Auto":
			m.setInput(stageAutoPath, "File path (.env or .dpx)", "", false)
			return m, nil
		}
	case stageEncryptFile:
		m.encryptReq = app.EncryptRequest{InputPath: selected}
		m.setMenu(stageEncryptMode, "Choose encryption mode", []string{"Age", "Password"})
	case stageEncryptMode:
		if selected == "Age" {
			m.encryptReq.Mode = envelope.ModeAge
			if len(m.cfg.Age.Recipients) > 0 {
				m.encryptReq.Recipients = append([]string{}, m.cfg.Age.Recipients...)
				m.setInput(stageEncryptOutput, "Output path", m.encryptReq.InputPath+m.cfg.DefaultSuffix, false)
			} else {
				m.setInput(stageEncryptRecipients, "Recipients (comma-separated)", "", false)
			}
		} else {
			m.encryptReq.Mode = envelope.ModePassword
			m.setInput(stageEncryptPassword, "Password", "", true)
		}
	case stageDecryptFile:
		return m.startDecrypt(selected)
	case stageInspectFile:
		return m.showInspectResult(selected)
	}
	return m, nil
}

func (m Model) submitInput() (tea.Model, tea.Cmd) {
	value := strings.TrimSpace(m.input.Value())
	switch m.stage {
	case stageAutoPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		if isEncryptedPath(value, m.cfg.DefaultSuffix) {
			return m.startDecrypt(value)
		}
		m.encryptReq = app.EncryptRequest{
			InputPath: value,
			Mode:      envelope.ModePassword,
		}
		m.setInput(stageEncryptPassword, "Password", "", true)
	case stageEncryptManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		m.encryptReq = app.EncryptRequest{InputPath: value}
		m.setMenu(stageEncryptMode, "Choose encryption mode", []string{"Age", "Password"})
	case stageEncryptPassword:
		m.encryptReq.Passphrase = []byte(value)
		m.setInput(stageEncryptOutput, "Output path", m.encryptReq.InputPath+m.cfg.DefaultSuffix, false)
	case stageEncryptRecipients:
		m.encryptReq.Recipients = splitCSV(value)
		m.setInput(stageEncryptOutput, "Output path", m.encryptReq.InputPath+m.cfg.DefaultSuffix, false)
	case stageEncryptOutput:
		m.encryptReq.OutputPath = value
		outputPath, err := m.svc.EncryptFile(m.encryptReq)
		if err != nil {
			return m.fail(err)
		}
		m.stage = stageResult
		m.title = "Encrypt Result"
		m.help = "Press Enter or q to exit"
		m.result = fmt.Sprintf("Encrypted %s -> %s", m.encryptReq.InputPath, outputPath)
		if !m.interactive {
			return m, tea.Quit
		}
	case stageDecryptManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		return m.startDecrypt(value)
	case stageDecryptPassword:
		m.decryptReq.Passphrase = []byte(value)
		m.setInput(stageDecryptOutput, "Output path (blank uses original name)", "", false)
	case stageDecryptOutput:
		m.decryptReq.OutputPath = value
		outputPath, err := m.svc.DecryptFile(m.decryptReq)
		if err != nil {
			return m.fail(err)
		}
		m.stage = stageResult
		m.title = "Decrypt Result"
		m.help = "Press Enter or q to exit"
		m.result = fmt.Sprintf("Decrypted %s -> %s", m.decryptReq.InputPath, outputPath)
		if !m.interactive {
			return m, tea.Quit
		}
	case stageInspectManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		return m.showInspectResult(value)
	}
	return m, nil
}

func (m Model) startDecrypt(path string) (tea.Model, tea.Cmd) {
	m.decryptReq = app.DecryptRequest{InputPath: path}
	meta, err := m.svc.Inspect(path)
	if err != nil {
		return m.fail(err)
	}
	m.decryptMeta = meta
	if meta.Mode == envelope.ModePassword {
		m.setInput(stageDecryptPassword, "Password", "", true)
	} else {
		m.setInput(stageDecryptOutput, "Output path (blank uses original name)", "", false)
	}
	return m, nil
}

func (m Model) showInspectResult(path string) (tea.Model, tea.Cmd) {
	meta, err := m.svc.Inspect(path)
	if err != nil {
		return m.fail(err)
	}
	m.stage = stageResult
	m.title = "Inspect Result"
	m.help = "Press Enter or q to exit"
	m.result = fmt.Sprintf("Version: %d\nMode: %s\nOriginal Name: %s\nCreated At: %s", meta.Version, meta.Mode, meta.OriginalName, meta.CreatedAt.Format("2006-01-02 15:04:05Z07:00"))
	if !m.interactive {
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) fail(err error) (tea.Model, tea.Cmd) {
	m.err = err
	m.stage = stageResult
	m.title = "Error"
	m.help = "Press Enter or q to exit"
	m.result = "Error: " + err.Error()
	if !m.interactive {
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) setMenu(next stage, title string, options []string) {
	m.stage = next
	m.title = title
	m.help = "1-9 choose, Enter confirm, arrow keys move, q quits"
	m.options = options
	m.selection = 0
}

func (m *Model) setInput(next stage, title, value string, password bool) {
	input := textinput.New()
	input.Prompt = title + ": "
	input.SetValue(value)
	input.CursorEnd()
	input.Focus()
	if password {
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '•'
	}
	m.stage = next
	m.title = title
	m.help = "Type and press Enter to continue, q quits"
	m.input = input
}

func candidateLabels(candidates []discovery.Candidate) []string {
	labels := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		labels = append(labels, candidate.Path)
	}
	return labels
}

func findEncryptedFiles(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".dpx") {
			files = append(files, filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func isEncryptedPath(path, defaultSuffix string) bool {
	if strings.HasSuffix(path, ".dpx") {
		return true
	}
	if defaultSuffix != "" && defaultSuffix != ".dpx" && strings.HasSuffix(path, defaultSuffix) {
		return true
	}
	return false
}

func splitCSV(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	parts := strings.Split(text, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
