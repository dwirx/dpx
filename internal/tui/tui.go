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
	"github.com/dwirx/dpx/internal/crypto/password"
	"github.com/dwirx/dpx/internal/discovery"
	"github.com/dwirx/dpx/internal/envelope"
	"github.com/dwirx/dpx/internal/policy"
	"github.com/dwirx/dpx/internal/safeio"
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
	stageEnvEncryptFile
	stageEnvEncryptManualPath
	stageEnvEncryptMode
	stageEnvEncryptKeys
	stageEnvEncryptPassword
	stageEnvEncryptPasswordConfirm
	stageEnvEncryptRecipients
	stageEnvEncryptOutput
	stageEnvDecryptFile
	stageEnvDecryptManualPath
	stageEnvDecryptPassword
	stageEnvDecryptPasswordConfirm
	stageEnvDecryptOutput
	stageEnvSetFile
	stageEnvSetManualPath
	stageEnvSetKey
	stageEnvSetValue
	stageEnvSetMode
	stageEnvSetPassword
	stageEnvSetPasswordConfirm
	stageEnvSetRecipients
	stageEnvSetOutput
	stageEnvUpdateKeysFile
	stageEnvUpdateKeysManualPath
	stageEnvUpdateKeysRecipients
	stageEnvUpdateKeysKeys
	stageEnvUpdateKeysOutput
	stagePolicyFile
	stagePolicyManualPath
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
	stage         stage
	title         string
	help          string
	options       []string
	selection     int
	input         textinput.Model
	encryptReq    app.EncryptRequest
	passwordBuf   string
	encryptScope  encryptScope
	encryptQuery  string
	encryptAll    []string
	encryptShown  []string
	decryptReq    app.DecryptRequest
	decryptMeta   envelope.Metadata
	envEncryptReq app.EnvInlineEncryptRequest
	envDecryptReq app.EnvInlineDecryptRequest
	envSetReq     app.EnvInlineSetRequest
	envUpdateReq  app.EnvInlineUpdateRecipientsRequest
	policyPath    string
	envKeys       []string
	envHasAge     bool
	envHasPwd     bool
	importRaw     string
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

	encryptReq    app.EncryptRequest
	passwordBuf   string
	encryptScope  encryptScope
	encryptQuery  string
	encryptAll    []string
	encryptShown  []string
	decryptReq    app.DecryptRequest
	decryptMeta   envelope.Metadata
	envEncryptReq app.EnvInlineEncryptRequest
	envDecryptReq app.EnvInlineDecryptRequest
	envSetReq     app.EnvInlineSetRequest
	envUpdateReq  app.EnvInlineUpdateRecipientsRequest
	policyPath    string
	envKeys       []string
	envHasAge     bool
	envHasPwd     bool
	importRaw     string
	history       []navSnapshot
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
	m.applyMenu(stageAction, "Choose an action", []string{"Encrypt", "Decrypt", "Inspect", "Auto", "Import Key", "Doctor", "Env Inline Encrypt", "Env Inline Decrypt", "Env Set", "Env Update Keys", "Policy Check"})
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
		stageEnvEncryptManualPath,
		stageEnvEncryptKeys,
		stageEnvEncryptPassword,
		stageEnvEncryptPasswordConfirm,
		stageEnvEncryptRecipients,
		stageEnvEncryptOutput,
		stageEnvDecryptManualPath,
		stageEnvDecryptPassword,
		stageEnvDecryptPasswordConfirm,
		stageEnvDecryptOutput,
		stageEnvSetManualPath,
		stageEnvSetKey,
		stageEnvSetValue,
		stageEnvSetPassword,
		stageEnvSetPasswordConfirm,
		stageEnvSetRecipients,
		stageEnvSetOutput,
		stageEnvUpdateKeysManualPath,
		stageEnvUpdateKeysRecipients,
		stageEnvUpdateKeysKeys,
		stageEnvUpdateKeysOutput,
		stagePolicyManualPath,
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
		case "Env Inline Encrypt":
			candidates, err := m.svc.Discover(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			options := candidateLabels(candidates)
			options = append(options, manualEncryptPathOption)
			m.setMenu(stageEnvEncryptFile, "Select a .env file for inline encryption", options)
		case "Env Inline Decrypt":
			files, err := findEncryptedFiles(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			if len(files) == 0 {
				m.setInput(stageEnvDecryptManualPath, "Env .dpx file path", "", false)
				return m, nil
			}
			m.setMenu(stageEnvDecryptFile, "Select a .env.dpx file to decrypt", files)
		case "Env Set":
			candidates, err := m.svc.Discover(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			options := candidateLabels(candidates)
			options = append(options, manualEncryptPathOption)
			m.setMenu(stageEnvSetFile, "Select a .env file for env set", options)
		case "Env Update Keys":
			files, err := findEncryptedFiles(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			if len(files) == 0 {
				m.setInput(stageEnvUpdateKeysManualPath, "Env .dpx file path", "", false)
				return m, nil
			}
			options := append([]string{}, files...)
			options = append(options, manualEncryptPathOption)
			m.setMenu(stageEnvUpdateKeysFile, "Select a .env.dpx file to rotate recipients", options)
		case "Policy Check":
			candidates, err := m.svc.DiscoverEncryptTargets(m.cwd)
			if err != nil {
				return m.fail(err)
			}
			options := candidateLabels(candidates)
			options = append(options, manualEncryptPathOption)
			m.setMenu(stagePolicyFile, "Select a file for policy check", options)
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
			m.encryptReq.KDFProfile = password.KDFProfileHardened
			m.setInput(stageEncryptPassword, "Password", "", true)
		}
	case stageDecryptFile:
		return m.startDecrypt(selected)
	case stageEnvEncryptFile:
		if selected == manualEncryptPathOption {
			m.setInput(stageEnvEncryptManualPath, "Env file path", "", false)
			return m, nil
		}
		m.envEncryptReq = app.EnvInlineEncryptRequest{InputPath: selected}
		m.setMenu(stageEnvEncryptMode, "Choose inline env encryption mode", []string{"Age", "Password"})
	case stageEnvEncryptMode:
		if selected == "Age" {
			m.envEncryptReq.Mode = envelope.ModeAge
			m.envEncryptReq.Recipients = append([]string{}, m.cfg.Age.Recipients...)
		} else {
			m.envEncryptReq.Mode = envelope.ModePassword
			m.envEncryptReq.Recipients = nil
			m.envEncryptReq.KDFProfile = password.KDFProfileHardened
		}
		keys, err := m.svc.ListEnvInlineKeys(m.envEncryptReq.InputPath)
		if err != nil {
			return m.fail(err)
		}
		m.envKeys = keys
		hint := "Keys (comma-separated names or 'all')"
		m.setInput(stageEnvEncryptKeys, hint, "all", false)
	case stageEnvDecryptFile:
		return m.startEnvInlineDecrypt(selected)
	case stageEnvSetFile:
		if selected == manualEncryptPathOption {
			m.setInput(stageEnvSetManualPath, "Env file path", "", false)
			return m, nil
		}
		m.envSetReq = app.EnvInlineSetRequest{InputPath: selected}
		m.setInput(stageEnvSetKey, "Key name", "", false)
	case stageEnvSetMode:
		switch selected {
		case "Plaintext":
			m.envSetReq.Encrypt = false
			m.envSetReq.Mode = ""
			m.envSetReq.KDFProfile = ""
			m.envSetReq.Passphrase = nil
			m.envSetReq.Recipients = nil
			m.setInput(stageEnvSetOutput, "Output path (blank updates same file)", m.envSetReq.InputPath, false)
		case "Encrypt (Age)":
			m.envSetReq.Encrypt = true
			m.envSetReq.Mode = envelope.ModeAge
			m.envSetReq.Recipients = append([]string{}, m.cfg.Age.Recipients...)
			if len(m.envSetReq.Recipients) == 0 {
				m.setInput(stageEnvSetRecipients, "Recipients (comma-separated)", "", false)
			} else {
				m.setInput(stageEnvSetOutput, "Output path (blank updates same file)", m.envSetReq.InputPath, false)
			}
		case "Encrypt (Password)":
			m.envSetReq.Encrypt = true
			m.envSetReq.Mode = envelope.ModePassword
			m.envSetReq.KDFProfile = password.KDFProfileHardened
			m.setInput(stageEnvSetPassword, "Password", "", true)
		}
	case stageEnvUpdateKeysFile:
		if selected == manualEncryptPathOption {
			m.setInput(stageEnvUpdateKeysManualPath, "Env .dpx file path", "", false)
			return m, nil
		}
		m.envUpdateReq = app.EnvInlineUpdateRecipientsRequest{
			InputPath:    selected,
			IdentityPath: m.cfg.KeyFile,
		}
		m.setInput(stageEnvUpdateKeysRecipients, "Recipients (comma-separated)", "", false)
	case stagePolicyFile:
		if selected == manualEncryptPathOption {
			m.setInput(stagePolicyManualPath, "File path", "", false)
			return m, nil
		}
		return m.showPolicyResult(selected)
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
	rawValue := m.input.Value()
	value := strings.TrimSpace(rawValue)
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
	case stageEnvEncryptManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		m.envEncryptReq = app.EnvInlineEncryptRequest{InputPath: value}
		m.setMenu(stageEnvEncryptMode, "Choose inline env encryption mode", []string{"Age", "Password"})
	case stageEnvEncryptKeys:
		selectedKeys, err := parseEnvKeysInput(value, m.envKeys)
		if err != nil {
			m.help = err.Error()
			return m, nil
		}
		m.envEncryptReq.SelectedKeys = selectedKeys
		if m.envEncryptReq.Mode == envelope.ModePassword {
			m.setInput(stageEnvEncryptPassword, "Password", "", true)
			return m, nil
		}
		if len(m.envEncryptReq.Recipients) == 0 {
			m.setInput(stageEnvEncryptRecipients, "Recipients (comma-separated)", "", false)
			return m, nil
		}
		m.setInput(stageEnvEncryptOutput, "Output path", m.envEncryptReq.InputPath+m.cfg.DefaultSuffix, false)
	case stageEnvEncryptPassword:
		if value == "" {
			m.help = "Password is required, q quits"
			return m, nil
		}
		m.passwordBuf = value
		m.setInput(stageEnvEncryptPasswordConfirm, "Confirm password", "", true)
	case stageEnvEncryptPasswordConfirm:
		if value == "" {
			m.help = "Confirm password is required, q quits"
			return m, nil
		}
		if value != m.passwordBuf {
			m.passwordBuf = ""
			m.envEncryptReq.Passphrase = nil
			m.applyInput(stageEnvEncryptPassword, "Password", "", true)
			m.help = "Password confirmation mismatch. Re-enter password, q quits"
			return m, nil
		}
		m.envEncryptReq.Passphrase = []byte(value)
		m.passwordBuf = ""
		m.setInput(stageEnvEncryptOutput, "Output path", m.envEncryptReq.InputPath+m.cfg.DefaultSuffix, false)
	case stageEnvEncryptRecipients:
		m.envEncryptReq.Recipients = splitCSV(value)
		m.setInput(stageEnvEncryptOutput, "Output path", m.envEncryptReq.InputPath+m.cfg.DefaultSuffix, false)
	case stageEnvEncryptOutput:
		m.envEncryptReq.OutputPath = value
		result, err := m.svc.EncryptEnvInlineFile(m.envEncryptReq)
		if err != nil {
			return m.fail(err)
		}
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Env Encrypt Result"
		m.help = "Press Enter to exit, Esc back, q quits"
		m.result = fmt.Sprintf("Env inline encrypted %s -> %s\nUpdated keys (%d): %s", m.envEncryptReq.InputPath, result.OutputPath, len(result.Updated), strings.Join(result.Updated, ", "))
		if !m.interactive {
			return m, tea.Quit
		}
	case stageEnvDecryptManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		return m.startEnvInlineDecrypt(value)
	case stageEnvDecryptPassword:
		if value == "" {
			m.help = "Password is required, q quits"
			return m, nil
		}
		m.passwordBuf = value
		m.setInput(stageEnvDecryptPasswordConfirm, "Confirm password", "", true)
	case stageEnvDecryptPasswordConfirm:
		if value == "" {
			m.help = "Confirm password is required, q quits"
			return m, nil
		}
		if value != m.passwordBuf {
			m.passwordBuf = ""
			m.envDecryptReq.Passphrase = nil
			m.applyInput(stageEnvDecryptPassword, "Password", "", true)
			m.help = "Password confirmation mismatch. Re-enter password, q quits"
			return m, nil
		}
		m.envDecryptReq.Passphrase = []byte(value)
		m.passwordBuf = ""
		m.setInput(stageEnvDecryptOutput, "Output path (blank keeps default)", "", false)
	case stageEnvDecryptOutput:
		m.envDecryptReq.OutputPath = value
		result, err := m.svc.DecryptEnvInlineFile(m.envDecryptReq)
		if err != nil {
			return m.fail(err)
		}
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Env Decrypt Result"
		m.help = "Press Enter to exit, Esc back, q quits"
		m.result = fmt.Sprintf("Env inline decrypted %s -> %s\nUpdated keys (%d): %s", m.envDecryptReq.InputPath, result.OutputPath, len(result.Updated), strings.Join(result.Updated, ", "))
		if !m.interactive {
			return m, tea.Quit
		}
	case stageEnvSetManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		m.envSetReq = app.EnvInlineSetRequest{InputPath: value}
		m.setInput(stageEnvSetKey, "Key name", "", false)
	case stageEnvSetKey:
		if value == "" {
			m.help = "Key name is required, q quits"
			return m, nil
		}
		m.envSetReq.Key = value
		m.setInput(stageEnvSetValue, "Value", "", false)
	case stageEnvSetValue:
		m.envSetReq.Value = rawValue
		m.setMenu(stageEnvSetMode, "Set mode", []string{"Plaintext", "Encrypt (Age)", "Encrypt (Password)"})
	case stageEnvSetPassword:
		if value == "" {
			m.help = "Password is required, q quits"
			return m, nil
		}
		m.passwordBuf = rawValue
		m.setInput(stageEnvSetPasswordConfirm, "Confirm password", "", true)
	case stageEnvSetPasswordConfirm:
		if value == "" {
			m.help = "Confirm password is required, q quits"
			return m, nil
		}
		if rawValue != m.passwordBuf {
			m.passwordBuf = ""
			m.envSetReq.Passphrase = nil
			m.applyInput(stageEnvSetPassword, "Password", "", true)
			m.help = "Password confirmation mismatch. Re-enter password, q quits"
			return m, nil
		}
		m.envSetReq.Passphrase = []byte(rawValue)
		m.passwordBuf = ""
		m.setInput(stageEnvSetOutput, "Output path (blank updates same file)", m.envSetReq.InputPath, false)
	case stageEnvSetRecipients:
		m.envSetReq.Recipients = splitCSV(value)
		if len(m.envSetReq.Recipients) == 0 {
			m.help = "At least one recipient is required, q quits"
			return m, nil
		}
		m.setInput(stageEnvSetOutput, "Output path (blank updates same file)", m.envSetReq.InputPath, false)
	case stageEnvSetOutput:
		m.envSetReq.OutputPath = value
		result, err := m.svc.SetEnvInlineValue(m.envSetReq)
		if err != nil {
			return m.fail(err)
		}
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Env Set Result"
		m.help = "Press Enter to exit, Esc back, q quits"
		m.result = fmt.Sprintf("Env value updated in %s\nOutput: %s\nUpdated keys (%d): %s", m.envSetReq.InputPath, result.OutputPath, len(result.Updated), strings.Join(result.Updated, ", "))
		if !m.interactive {
			return m, tea.Quit
		}
	case stageEnvUpdateKeysManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		m.envUpdateReq = app.EnvInlineUpdateRecipientsRequest{
			InputPath:    value,
			IdentityPath: m.cfg.KeyFile,
		}
		m.setInput(stageEnvUpdateKeysRecipients, "Recipients (comma-separated)", "", false)
	case stageEnvUpdateKeysRecipients:
		m.envUpdateReq.Recipients = splitCSV(value)
		if len(m.envUpdateReq.Recipients) == 0 {
			m.help = "At least one recipient is required, q quits"
			return m, nil
		}
		m.setInput(stageEnvUpdateKeysKeys, "Keys (comma-separated names or 'all')", "all", false)
	case stageEnvUpdateKeysKeys:
		keys, err := m.svc.ListEnvInlineAgeEncryptedKeys(m.envUpdateReq.InputPath)
		if err != nil {
			return m.fail(err)
		}
		if len(keys) == 0 {
			m.help = "No age-encrypted keys found, q quits"
			return m, nil
		}
		selectedKeys, err := parseEnvKeysInput(value, keys)
		if err != nil {
			m.help = err.Error()
			return m, nil
		}
		m.envUpdateReq.SelectedKeys = selectedKeys
		m.setInput(stageEnvUpdateKeysOutput, "Output path (blank updates same file)", m.envUpdateReq.InputPath, false)
	case stageEnvUpdateKeysOutput:
		m.envUpdateReq.OutputPath = value
		result, err := m.svc.UpdateEnvInlineRecipients(m.envUpdateReq)
		if err != nil {
			return m.fail(err)
		}
		m.pushHistory()
		m.err = nil
		m.stage = stageResult
		m.title = "Env Update Keys Result"
		m.help = "Press Enter to exit, Esc back, q quits"
		m.result = fmt.Sprintf("Recipients updated in %s\nOutput: %s\nUpdated keys (%d): %s", m.envUpdateReq.InputPath, result.OutputPath, len(result.Updated), strings.Join(result.Updated, ", "))
		if !m.interactive {
			return m, tea.Quit
		}
	case stagePolicyManualPath:
		if value == "" {
			m.help = "File path is required, q quits"
			return m, nil
		}
		return m.showPolicyResult(value)
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

func (m Model) startEnvInlineDecrypt(path string) (tea.Model, tea.Cmd) {
	hasAge, hasPassword, err := m.svc.DetectEnvInlineModes(path)
	if err != nil {
		return m.fail(err)
	}
	m.envHasAge = hasAge
	m.envHasPwd = hasPassword
	m.envDecryptReq = app.EnvInlineDecryptRequest{
		InputPath:    path,
		IdentityPath: m.cfg.KeyFile,
	}
	if !hasAge {
		m.envDecryptReq.IdentityPath = ""
	}
	if hasPassword {
		m.setInput(stageEnvDecryptPassword, "Password", "", true)
	} else {
		m.setInput(stageEnvDecryptOutput, "Output path (blank keeps default)", "", false)
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

func (m Model) showPolicyResult(path string) (tea.Model, tea.Cmd) {
	data, err := safeio.ReadFile(path)
	if err != nil {
		return m.fail(err)
	}
	report := policy.Check(path, data)

	var out strings.Builder
	if report.SkipReason != "" {
		out.WriteString(fmt.Sprintf("Policy OK (%s)\n", report.SkipReason))
	} else if len(report.Findings) == 0 {
		out.WriteString(fmt.Sprintf("Policy OK: no plaintext sensitive keys found (%s)\n", report.Format))
	} else {
		out.WriteString(fmt.Sprintf("Policy findings: %d (%s)\n", len(report.Findings), report.Format))
		for _, finding := range report.Findings {
			if finding.Line > 0 {
				out.WriteString(fmt.Sprintf("- line %d key=%s: %s\n", finding.Line, finding.Key, finding.Reason))
			} else {
				out.WriteString(fmt.Sprintf("- key=%s: %s\n", finding.Key, finding.Reason))
			}
		}
	}

	m.pushHistory()
	m.err = nil
	m.stage = stageResult
	m.title = "Policy Result"
	m.help = "Press Enter to exit, Esc back, q quits"
	m.result = strings.TrimSpace(out.String())
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
	case stageEncryptPassword,
		stageEncryptPasswordConfirm,
		stageDecryptPassword,
		stageEnvEncryptPassword,
		stageEnvEncryptPasswordConfirm,
		stageEnvDecryptPassword,
		stageEnvDecryptPasswordConfirm,
		stageEnvSetPassword,
		stageEnvSetPasswordConfirm,
		stageImportRaw:
		return true
	default:
		return false
	}
}

func (m *Model) pushHistory() {
	snapshot := navSnapshot{
		stage:         m.stage,
		title:         m.title,
		help:          m.help,
		options:       append([]string{}, m.options...),
		selection:     m.selection,
		input:         m.input,
		encryptReq:    cloneEncryptRequest(m.encryptReq),
		passwordBuf:   m.passwordBuf,
		encryptScope:  m.encryptScope,
		encryptQuery:  m.encryptQuery,
		encryptAll:    append([]string{}, m.encryptAll...),
		encryptShown:  append([]string{}, m.encryptShown...),
		decryptReq:    cloneDecryptRequest(m.decryptReq),
		decryptMeta:   m.decryptMeta,
		envEncryptReq: cloneEnvEncryptRequest(m.envEncryptReq),
		envDecryptReq: cloneEnvDecryptRequest(m.envDecryptReq),
		envSetReq:     cloneEnvSetRequest(m.envSetReq),
		envUpdateReq:  cloneEnvUpdateRecipientsRequest(m.envUpdateReq),
		policyPath:    m.policyPath,
		envKeys:       append([]string{}, m.envKeys...),
		envHasAge:     m.envHasAge,
		envHasPwd:     m.envHasPwd,
		importRaw:     m.importRaw,
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
	m.envEncryptReq = cloneEnvEncryptRequest(last.envEncryptReq)
	m.envDecryptReq = cloneEnvDecryptRequest(last.envDecryptReq)
	m.envSetReq = cloneEnvSetRequest(last.envSetReq)
	m.envUpdateReq = cloneEnvUpdateRecipientsRequest(last.envUpdateReq)
	m.policyPath = last.policyPath
	m.envKeys = append([]string{}, last.envKeys...)
	m.envHasAge = last.envHasAge
	m.envHasPwd = last.envHasPwd
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

func cloneEnvEncryptRequest(req app.EnvInlineEncryptRequest) app.EnvInlineEncryptRequest {
	cloned := req
	cloned.Passphrase = append([]byte(nil), req.Passphrase...)
	cloned.Recipients = append([]string{}, req.Recipients...)
	cloned.SelectedKeys = append([]string{}, req.SelectedKeys...)
	return cloned
}

func cloneEnvDecryptRequest(req app.EnvInlineDecryptRequest) app.EnvInlineDecryptRequest {
	cloned := req
	cloned.Passphrase = append([]byte(nil), req.Passphrase...)
	return cloned
}

func cloneEnvSetRequest(req app.EnvInlineSetRequest) app.EnvInlineSetRequest {
	cloned := req
	cloned.Passphrase = append([]byte(nil), req.Passphrase...)
	cloned.Recipients = append([]string{}, req.Recipients...)
	return cloned
}

func cloneEnvUpdateRecipientsRequest(req app.EnvInlineUpdateRecipientsRequest) app.EnvInlineUpdateRecipientsRequest {
	cloned := req
	cloned.Recipients = append([]string{}, req.Recipients...)
	cloned.SelectedKeys = append([]string{}, req.SelectedKeys...)
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

func parseEnvKeysInput(raw string, available []string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.EqualFold(value, "all") {
		return append([]string{}, available...), nil
	}
	requested := splitCSV(value)
	if len(requested) == 0 {
		return nil, fmt.Errorf("no keys selected")
	}
	availableSet := make(map[string]struct{}, len(available))
	for _, key := range available {
		availableSet[key] = struct{}{}
	}
	selected := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, key := range requested {
		if _, ok := availableSet[key]; !ok {
			return nil, fmt.Errorf("unknown env key %q", key)
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, key)
	}
	return selected, nil
}

func fileDescriptorInt(file *os.File) (int, bool) {
	fd := file.Fd()
	maxInt := ^uintptr(0) >> 1
	if fd > maxInt {
		return 0, false
	}
	return int(fd), true
}
