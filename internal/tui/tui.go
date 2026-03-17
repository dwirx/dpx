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
	stageEncryptSearchQuery
	stageEncryptManualPath
	stageEncryptMode
	stageEncryptPassword
	stageEncryptPasswordConfirm
	stageEncryptRecipients
	stageEncryptOutput
	stageDecryptFile
	stageDecryptManualPath
	stageDecryptPassword
	stageDecryptOutput
	stageInspectFile
	stageInspectManualPath
	stageImportSource
	stageImportFilePath
	stageImportRaw
	stageImportOutput
	stageResult
)

const manualEncryptPathOption = "[manual] Enter custom file path"
const searchEncryptPathOption = "[search] Find file by keyword"

type encryptScope string

const (
	encryptScopeAny encryptScope = "any"
	encryptScopeEnv encryptScope = "env"
)

type navSnapshot struct {
	stage        stage
	title        string
	help         string
	options      []string
	selection    int
	input        textinput.Model
	encryptReq   app.EncryptRequest
	passwordBuf  string
	encryptScope encryptScope
	encryptQuery string
	encryptAll   []string
	encryptShown []string
	decryptReq   app.DecryptRequest
	decryptMeta  envelope.Metadata
	importRaw    string
}

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

	encryptReq   app.EncryptRequest
	passwordBuf  string
	encryptScope encryptScope
	encryptQuery string
	encryptAll   []string
	encryptShown []string
	decryptReq   app.DecryptRequest
	decryptMeta  envelope.Metadata
	importRaw    string
	history      []navSnapshot
}

func Run(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) error {
	model, err := NewModel(svc, cfg, cwd, stdin, stdout)
	if err != nil {
		return err
	}
	options := []tea.ProgramOption{tea.WithInput(stdin), tea.WithOutput(stdout)}
	if file, ok := stdout.(*os.File); ok {
		if fd, fdOK := fileDescriptorInt(file); fdOK && term.IsTerminal(fd) {
			options = append(options, tea.WithAltScreen())
		}
	}
	final, err := tea.NewProgram(model, options...).Run()
	if err != nil {
		return err
	}
	return final.(Model).err
}

func NewModel(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) (Model, error) {
	interactive := false
	if file, ok := stdout.(*os.File); ok {
		if fd, fdOK := fileDescriptorInt(file); fdOK && term.IsTerminal(fd) {
			interactive = true
		}
	}
	m := Model{svc: svc, cfg: cfg, cwd: cwd, stdin: stdin, stdout: stdout, interactive: interactive}
	m.applyMenu(stageAction, "Choose an action", []string{"Encrypt", "Decrypt", "Inspect", "Auto", "Import Key", "Doctor"})
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
			if msg.String() == "enter" {
				return m, tea.Quit
			}
			if msg.String() == "esc" {
				if m.goBack() {
					return m, nil
				}
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
	searchMatchStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	boxStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Width(76)

	var body strings.Builder
	body.WriteString(titleStyle.Render("DPX TUI"))
	body.WriteString("\n")
	body.WriteString(helpStyle.Render("Full-screen workflow for encrypt, decrypt, inspect, import, and doctor"))
	body.WriteString("\n\n")
	body.WriteString(subtitleStyle.Render(m.title))
	body.WriteString("\n\n")

	if m.isInputStage() {
		body.WriteString(m.input.View())
		body.WriteString("\n")
		if m.stage == stageEncryptSearchQuery {
			body.WriteString("\n")
			body.WriteString(helpStyle.Render(fmt.Sprintf("Suggestions: %d", len(m.encryptShown))))
			body.WriteString("\n")
			body.WriteString(renderSearchSuggestions(m.encryptShown, m.encryptQuery, searchMatchStyle))
		}
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
		stageEncryptSearchQuery,
		stageEncryptManualPath,
		stageEncryptPassword,
		stageEncryptPasswordConfirm,
		stageEncryptRecipients,
		stageEncryptOutput,
		stageDecryptManualPath,
		stageDecryptPassword,
		stageDecryptOutput,
		stageInspectManualPath,
		stageImportFilePath,
		stageImportRaw,
		stageImportOutput:
		return true
	default:
		return false
	}
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		if m.goBack() {
			return m, nil
		}
		return m, nil
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
	if msg.String() == "esc" {
		if m.goBack() {
			return m, nil
		}
		return m, nil
	}
	if msg.String() == "ctrl+v" && m.togglePasswordVisibility() {
		return m, nil
	}
	if msg.String() == "enter" {
		return m.submitInput()
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.stage == stageEncryptSearchQuery {
		m.syncEncryptSearchSuggestions()
	}
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
			m.encryptScope = encryptScopeAny
			if err := m.refreshEncryptCandidates(); err != nil {
				return m.fail(err)
			}
			m.setEncryptFileMenu()
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
			m.setInput(stageAutoPath, "File path (any file or .dpx)", "", false)
			return m, nil
		case "Import Key":
			m.setMenu(stageImportSource, "Import source", []string{"From file", "Paste private key"})
		case "Doctor":
			report, err := collectDoctorReportForTUI(m.svc, m.cwd, m.cfg)
			if err != nil {
				return m.fail(err)
			}
			m.pushHistory()
			m.err = nil
			m.stage = stageResult
			m.title = "Doctor Result"
			m.help = "Press Enter to exit, Esc back, q quits"
			m.result = formatDoctorReport(report)
			if !m.interactive {
				return m, tea.Quit
			}
		}
	case stageEncryptFile:
		switch selected {
		case manualEncryptPathOption:
			m.setInput(stageEncryptManualPath, "File to encrypt", "", false)
			return m, nil
		case searchEncryptPathOption:
			if len(m.encryptAll) == 0 {
				m.help = "No files available to search in current mode, Esc back, q quits"
				return m, nil
			}
			m.setInput(stageEncryptSearchQuery, "Search filename", m.encryptQuery, false)
			return m, nil
		case encryptScopeSwitchOption(m.encryptScope):
			m.encryptScope = toggleEncryptScope(m.encryptScope)
			if err := m.refreshEncryptCandidates(); err != nil {
				return m.fail(err)
			}
			m.setEncryptFileMenu()
			return m, nil
		}
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
	case stageImportSource:
		if selected == "From file" {
			m.setInput(stageImportFilePath, "Path to age key file", "", false)
		} else {
			m.setInput(stageImportRaw, "Private key (AGE-SECRET-KEY-...)", "", true)
		}
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
	case stageEncryptSearchQuery:
		if value == "" {
			m.encryptShown = append([]string{}, m.encryptAll...)
			m.setEncryptFileMenu()
			return m, nil
		}
		filtered := filterPathsByQuery(m.encryptAll, value)
		if len(filtered) == 0 {
			m.help = fmt.Sprintf("No files match %q. Try another keyword, Esc back, q quits", value)
			return m, nil
		}
		m.encryptShown = filtered
		m.setEncryptFileMenu()
		return m, nil
	case stageEncryptManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		m.encryptReq = app.EncryptRequest{InputPath: value}
		m.setMenu(stageEncryptMode, "Choose encryption mode", []string{"Age", "Password"})
	case stageEncryptPassword:
		if value == "" {
			m.help = "Password is required, q quits"
			return m, nil
		}
		m.passwordBuf = value
		m.setInput(stageEncryptPasswordConfirm, "Confirm password", "", true)
	case stageEncryptPasswordConfirm:
		if value == "" {
			m.help = "Confirm password is required, q quits"
			return m, nil
		}
		if value != m.passwordBuf {
			m.passwordBuf = ""
			m.encryptReq.Passphrase = nil
			m.applyInput(stageEncryptPassword, "Password", "", true)
			m.help = "Password confirmation mismatch. Re-enter password, q quits"
			return m, nil
		}
		m.encryptReq.Passphrase = []byte(value)
		m.passwordBuf = ""
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
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Encrypt Result"
		m.help = "Press Enter to exit, Esc back, q quits"
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
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Decrypt Result"
		m.help = "Press Enter to exit, Esc back, q quits"
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
	case stageImportFilePath:
		if value == "" {
			m.help = "Import file path is required, q quits"
			return m, nil
		}
		data, err := os.ReadFile(expandHome(value))
		if err != nil {
			return m.fail(err)
		}
		m.importRaw = string(data)
		m.setInput(stageImportOutput, "Output key path", m.cfg.KeyFile, false)
	case stageImportRaw:
		if value == "" {
			m.help = "Private key is required, q quits"
			return m, nil
		}
		m.importRaw = value
		m.setInput(stageImportOutput, "Output key path", m.cfg.KeyFile, false)
	case stageImportOutput:
		message, err := importIdentityAndSyncConfig(m.svc, m.cwd, m.cfg, value, m.importRaw)
		if err != nil {
			return m.fail(err)
		}
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Import Result"
		m.help = "Press Enter to exit, Esc back, q quits"
		m.result = message
		if !m.interactive {
			return m, tea.Quit
		}
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
	m.pushHistory()
	m.err = nil
	m.stage = stageResult
	m.title = "Inspect Result"
	m.help = "Press Enter to exit, Esc back, q quits"
	m.result = fmt.Sprintf("Version: %d\nMode: %s\nOriginal Name: %s\nCreated At: %s", meta.Version, meta.Mode, meta.OriginalName, meta.CreatedAt.Format("2006-01-02 15:04:05Z07:00"))
	if !m.interactive {
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) fail(err error) (tea.Model, tea.Cmd) {
	m.pushHistory()
	m.err = err
	m.stage = stageResult
	m.title = "Error"
	m.help = "Press Enter to exit, Esc back, q quits"
	m.result = "Error: " + err.Error()
	if !m.interactive {
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) setMenu(next stage, title string, options []string) {
	m.pushHistory()
	m.applyMenu(next, title, options)
}

func (m *Model) setInput(next stage, title, value string, password bool) {
	m.pushHistory()
	m.applyInput(next, title, value, password)
}

func (m *Model) applyMenu(next stage, title string, options []string) {
	m.stage = next
	m.title = title
	m.help = "1-9 choose, Enter confirm, arrow keys move, Esc back, q quits"
	m.options = append([]string{}, options...)
	m.selection = 0
}

func (m *Model) applyInput(next stage, title, value string, password bool) {
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
	if next == stageEncryptSearchQuery {
		m.help = "Type to search in realtime, Enter applies filter, Esc back, q quits"
	} else if password {
		m.help = "Type and press Enter, Ctrl+V toggles show/hide, Esc back, q quits"
	} else {
		m.help = "Type and press Enter to continue, Esc back, q quits"
	}
	m.input = input
	if next == stageEncryptSearchQuery {
		m.syncEncryptSearchSuggestions()
	}
}

func (m *Model) togglePasswordVisibility() bool {
	if !m.isPasswordInputStage() {
		return false
	}
	switch m.input.EchoMode {
	case textinput.EchoPassword:
		m.input.EchoMode = textinput.EchoNormal
	default:
		m.input.EchoMode = textinput.EchoPassword
		m.input.EchoCharacter = '•'
	}
	m.help = "Type and press Enter, Ctrl+V toggles show/hide, Esc back, q quits"
	return true
}

func (m Model) isPasswordInputStage() bool {
	switch m.stage {
	case stageEncryptPassword, stageEncryptPasswordConfirm, stageDecryptPassword, stageImportRaw:
		return true
	default:
		return false
	}
}

func (m *Model) pushHistory() {
	snapshot := navSnapshot{
		stage:        m.stage,
		title:        m.title,
		help:         m.help,
		options:      append([]string{}, m.options...),
		selection:    m.selection,
		input:        m.input,
		encryptReq:   cloneEncryptRequest(m.encryptReq),
		passwordBuf:  m.passwordBuf,
		encryptScope: m.encryptScope,
		encryptQuery: m.encryptQuery,
		encryptAll:   append([]string{}, m.encryptAll...),
		encryptShown: append([]string{}, m.encryptShown...),
		decryptReq:   cloneDecryptRequest(m.decryptReq),
		decryptMeta:  m.decryptMeta,
		importRaw:    m.importRaw,
	}
	m.history = append(m.history, snapshot)
}

func (m *Model) goBack() bool {
	if len(m.history) == 0 {
		return false
	}
	last := m.history[len(m.history)-1]
	m.history = m.history[:len(m.history)-1]
	m.stage = last.stage
	m.title = last.title
	m.help = last.help
	m.options = append([]string{}, last.options...)
	m.selection = last.selection
	m.input = last.input
	m.encryptReq = cloneEncryptRequest(last.encryptReq)
	m.passwordBuf = last.passwordBuf
	m.encryptScope = last.encryptScope
	m.encryptQuery = last.encryptQuery
	m.encryptAll = append([]string{}, last.encryptAll...)
	m.encryptShown = append([]string{}, last.encryptShown...)
	m.decryptReq = cloneDecryptRequest(last.decryptReq)
	m.decryptMeta = last.decryptMeta
	m.importRaw = last.importRaw
	m.result = ""
	m.err = nil
	return true
}

func cloneEncryptRequest(req app.EncryptRequest) app.EncryptRequest {
	cloned := req
	cloned.Passphrase = append([]byte(nil), req.Passphrase...)
	cloned.Recipients = append([]string{}, req.Recipients...)
	return cloned
}

func cloneDecryptRequest(req app.DecryptRequest) app.DecryptRequest {
	cloned := req
	cloned.Passphrase = append([]byte(nil), req.Passphrase...)
	return cloned
}

func candidateLabels(candidates []discovery.Candidate) []string {
	labels := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		labels = append(labels, candidate.Path)
	}
	return labels
}

func encryptOptions(candidates []discovery.Candidate) []string {
	options := candidateLabels(candidates)
	options = append(options, manualEncryptPathOption)
	return options
}

func (m *Model) refreshEncryptCandidates() error {
	var (
		candidates []discovery.Candidate
		err        error
	)
	switch m.encryptScope {
	case encryptScopeEnv:
		candidates, err = m.svc.Discover(m.cwd)
	default:
		candidates, err = m.svc.DiscoverEncryptTargets(m.cwd)
	}
	if err != nil {
		return err
	}
	m.encryptQuery = ""
	m.encryptAll = candidateLabels(candidates)
	m.encryptShown = append([]string{}, m.encryptAll...)
	return nil
}

func (m *Model) syncEncryptSearchSuggestions() {
	query := strings.TrimSpace(m.input.Value())
	m.encryptQuery = query
	if query == "" {
		m.encryptShown = append([]string{}, m.encryptAll...)
		m.help = "Type to search in realtime, Enter applies filter, Esc back, q quits"
		return
	}
	filtered := filterPathsByQuery(m.encryptAll, query)
	m.encryptShown = filtered
	switch len(filtered) {
	case 0:
		m.help = fmt.Sprintf("No files match %q. Keep typing, Enter applies filter, Esc back, q quits", query)
	case 1:
		m.help = "1 suggestion found. Enter applies filter, Esc back, q quits"
	default:
		m.help = fmt.Sprintf("%d suggestions found. Enter applies filter, Esc back, q quits", len(filtered))
	}
}

func (m *Model) setEncryptFileMenu() {
	options := append([]string{}, m.encryptShown...)
	options = append(options, manualEncryptPathOption)
	if len(m.encryptAll) > 0 {
		options = append(options, searchEncryptPathOption)
	}
	options = append(options, encryptScopeSwitchOption(m.encryptScope))
	title := encryptScopeTitle(m.encryptScope)
	if len(m.encryptShown) != len(m.encryptAll) {
		title += " (filtered)"
	}
	m.setMenu(stageEncryptFile, title, options)
}

func encryptScopeSwitchOption(scope encryptScope) string {
	if scope == encryptScopeEnv {
		return "[scope] Switch to all files mode"
	}
	return "[scope] Switch to .env mode"
}

func toggleEncryptScope(scope encryptScope) encryptScope {
	if scope == encryptScopeEnv {
		return encryptScopeAny
	}
	return encryptScopeEnv
}

func encryptScopeTitle(scope encryptScope) string {
	if scope == encryptScopeEnv {
		return "Select a file to encrypt (.env mode)"
	}
	return "Select a file to encrypt (all files mode)"
}

func encryptScopeName(scope encryptScope) string {
	if scope == encryptScopeEnv {
		return ".env"
	}
	return "all files"
}

func filterPathsByQuery(paths []string, query string) []string {
	lower := strings.ToLower(query)
	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		base := strings.ToLower(filepath.Base(path))
		full := strings.ToLower(path)
		if strings.Contains(base, lower) || strings.Contains(full, lower) {
			filtered = append(filtered, path)
		}
	}
	return filtered
}

func splitSearchMatch(value, query string) (prefix, match, suffix string, ok bool) {
	lowerQuery := strings.ToLower(strings.TrimSpace(query))
	if lowerQuery == "" {
		return value, "", "", false
	}
	lowerValue := strings.ToLower(value)
	index := strings.Index(lowerValue, lowerQuery)
	if index < 0 {
		return value, "", "", false
	}
	end := index + len(lowerQuery)
	if end > len(value) {
		return value, "", "", false
	}
	return value[:index], value[index:end], value[end:], true
}

func highlightQueryMatch(value, query string, style lipgloss.Style) string {
	prefix, match, suffix, ok := splitSearchMatch(value, query)
	if !ok {
		return value
	}
	return prefix + style.Render(match) + suffix
}

func renderSearchSuggestions(paths []string, query string, highlightStyle lipgloss.Style) string {
	if len(paths) == 0 {
		return "  (no matches)\n"
	}
	const maxSuggestions = 8
	limit := len(paths)
	if limit > maxSuggestions {
		limit = maxSuggestions
	}
	var out strings.Builder
	for idx := 0; idx < limit; idx++ {
		path := highlightQueryMatch(paths[idx], query, highlightStyle)
		out.WriteString(fmt.Sprintf("  %d. %s\n", idx+1, path))
	}
	if len(paths) > maxSuggestions {
		out.WriteString(fmt.Sprintf("  ... and %d more\n", len(paths)-maxSuggestions))
	}
	return out.String()
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

func fileDescriptorInt(file *os.File) (int, bool) {
	fd := file.Fd()
	maxInt := ^uintptr(0) >> 1
	if fd > maxInt {
		return 0, false
	}
	return int(fd), true
}
