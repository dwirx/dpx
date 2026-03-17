package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"dopx/internal/app"
	"dopx/internal/config"
	"dopx/internal/discovery"
	"dopx/internal/envelope"
	"dopx/internal/tui"
)

var version = "dev"

const (
	appName          = "dpx"
	primaryConfig    = ".dpx.yaml"
	legacyConfig     = ".dopx.yaml"
	doctorTitle      = "DPX Doctor"
	legacyDoctorNote = "legacy"
)

type runOptions struct {
	cwd    string
	stdin  io.Reader
	reader *bufio.Reader
	stdout io.Writer
	stderr io.Writer
}

type configSource struct {
	Path   string
	Exists bool
	Legacy bool
}

type doctorReport struct {
	Config         configSource
	ConfigError    error
	KeyPath        string
	KeyExists      bool
	KeyUsesLegacy  bool
	RecipientCount int
	SuggestedFiles int
	EncryptedFiles int
}

func main() {
	if err := run(os.Args[1:], runOptions{
		cwd:    mustGetwd(),
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string, opts runOptions) error {
	if opts.cwd == "" {
		opts.cwd = mustGetwd()
	}
	if opts.stdin == nil {
		opts.stdin = strings.NewReader("")
	}
	if opts.reader == nil {
		opts.reader = bufio.NewReader(opts.stdin)
	}
	if opts.stdout == nil {
		opts.stdout = io.Discard
	}
	if opts.stderr == nil {
		opts.stderr = io.Discard
	}
	if len(args) == 0 {
		printUsage(opts.stdout)
		return nil
	}
	switch args[0] {
	case "version", "--version", "-v":
		printVersion(opts.stdout)
		return nil
	case "help", "--help", "-h":
		printUsage(opts.stdout)
		return nil
	case "init":
		return runInit(opts)
	case "doctor":
		return runDoctor(opts)
	}

	cfg, _, err := loadConfig(opts.cwd)
	if err != nil {
		return err
	}
	svc := app.New(cfg)

	switch args[0] {
	case "keygen":
		return runKeygen(svc, cfg, args[1:], opts)
	case "encrypt":
		return runEncrypt(svc, cfg, args[1:], opts)
	case "decrypt":
		return runDecrypt(svc, args[1:], opts)
	case "inspect":
		return runInspect(svc, args[1:], opts)
	case "tui":
		return runTUI(svc, cfg, opts)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInit(opts runOptions) error {
	source, err := resolveConfigSource(opts.cwd)
	if err != nil {
		return err
	}
	if source.Exists {
		return fmt.Errorf("config already exists: %s", source.Path)
	}
	cfgPath := filepath.Join(opts.cwd, primaryConfig)
	svc := app.New(config.Default())
	if err := svc.Init(cfgPath); err != nil {
		return err
	}
	fmt.Fprintln(opts.stdout, "✅ Created .dpx.yaml")
	fmt.Fprintln(opts.stdout)
	fmt.Fprintln(opts.stdout, "Next steps:")
	fmt.Fprintln(opts.stdout, "  1. Run 'dpx keygen' to generate a key pair")
	fmt.Fprintln(opts.stdout, "  2. Add your public key to .dpx.yaml")
	fmt.Fprintln(opts.stdout, "  3. Run 'dpx encrypt <file>' to encrypt your secrets")
	return nil
}

func runDoctor(opts runOptions) error {
	report, err := collectDoctorReport(opts.cwd)
	if err != nil {
		return err
	}
	printDoctorReport(opts.stdout, report)
	return nil
}

func runKeygen(svc app.Service, cfg config.Config, args []string, opts runOptions) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	outPath := fs.String("out", cfg.KeyFile, "path to write private key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	identity, err := svc.Keygen(expandHome(*outPath))
	if err != nil {
		return err
	}

	box := []string{
		"╔══════════════════════════════════════════════════════════════════╗",
		"║                  🔑 DPX Key Generated Successfully               ║",
		"╠══════════════════════════════════════════════════════════════════╣",
		"║ Backend: age                                                     ║",
		fmt.Sprintf("║ Key file: %-52s║", padRight(expandHome(*outPath), 52)),
		"╠══════════════════════════════════════════════════════════════════╣",
		"║ Public Key (add to .dpx.yaml):                                   ║",
		fmt.Sprintf("║   %-63s║", truncate(identity.PublicKey, 63)),
		"╚══════════════════════════════════════════════════════════════════╝",
	}
	for _, line := range box {
		fmt.Fprintln(opts.stdout, line)
	}
	return nil
}

func runEncrypt(svc app.Service, cfg config.Config, args []string, opts runOptions) error {
	parsed, err := parseEncryptArgs(args)
	if err != nil {
		return err
	}

	filePath := parsed.filePath
	if filePath == "" {
		candidates, err := svc.Discover(opts.cwd)
		if err != nil {
			return err
		}
		candidate, err := chooseCandidate(opts, "Select a file to encrypt", candidates)
		if err != nil {
			return err
		}
		filePath = candidate.Path
	}

	recipients := splitCSV(parsed.recipientsText)
	mode := chooseMode(parsed.passwordText, parsed.useAge, recipients, cfg)
	req := app.EncryptRequest{
		InputPath:  filePath,
		OutputPath: parsed.outPath,
		Mode:       mode,
		Recipients: recipients,
	}
	switch mode {
	case envelope.ModePassword:
		req.Passphrase = []byte(parsed.passwordText)
		if len(req.Passphrase) == 0 {
			pass, err := promptSecret(opts, "Password: ")
			if err != nil {
				return err
			}
			req.Passphrase = []byte(pass)
		}
	case envelope.ModeAge:
		if len(req.Recipients) == 0 {
			req.Recipients = cfg.Age.Recipients
		}
	}

	outputPath, err := svc.EncryptFile(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout, "Encrypted %s -> %s\n", req.InputPath, outputPath)
	return nil
}

func runDecrypt(svc app.Service, args []string, opts runOptions) error {
	parsed, err := parseDecryptArgs(args)
	if err != nil {
		return err
	}

	filePath := parsed.filePath
	if filePath == "" {
		files, err := findEncryptedFiles(opts.cwd)
		if err != nil {
			return err
		}
		choice, err := chooseString(opts, "Select a file to decrypt", files)
		if err != nil {
			return err
		}
		filePath = choice
	}

	meta, err := svc.Inspect(filePath)
	if err != nil {
		return err
	}
	req := app.DecryptRequest{InputPath: filePath, OutputPath: parsed.outPath, IdentityPath: parsed.identityPath}
	if meta.Mode == envelope.ModePassword {
		req.Passphrase = []byte(parsed.passwordText)
		if len(req.Passphrase) == 0 {
			pass, err := promptSecret(opts, "Password: ")
			if err != nil {
				return err
			}
			req.Passphrase = []byte(pass)
		}
	}
	outputPath, err := svc.DecryptFile(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout, "Decrypted %s -> %s\n", filePath, outputPath)
	return nil
}

func runInspect(svc app.Service, args []string, opts runOptions) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("inspect requires a .dpx file")
	}
	meta, err := svc.Inspect(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.stdout, "Version: %d\n", meta.Version)
	fmt.Fprintf(opts.stdout, "Mode: %s\n", meta.Mode)
	fmt.Fprintf(opts.stdout, "Original Name: %s\n", meta.OriginalName)
	fmt.Fprintf(opts.stdout, "Created At: %s\n", meta.CreatedAt.Format("2006-01-02 15:04:05Z07:00"))
	if meta.KDF != nil {
		fmt.Fprintf(opts.stdout, "KDF: %s\n", meta.KDF.Algorithm)
	}
	return nil
}

func runTUI(svc app.Service, cfg config.Config, opts runOptions) error {
	inFile, inTTY := opts.stdin.(*os.File)
	outFile, outTTY := opts.stdout.(*os.File)
	if inTTY && outTTY && term.IsTerminal(int(inFile.Fd())) && term.IsTerminal(int(outFile.Fd())) {
		return tui.Run(svc, cfg, opts.cwd, opts.stdin, opts.stdout)
	}
	return tui.RunFallback(svc, cfg, opts.cwd, opts.stdin, opts.stdout)
}

func chooseMode(passwordText string, useAge bool, recipients []string, cfg config.Config) string {
	if passwordText != "" {
		return envelope.ModePassword
	}
	if useAge || len(recipients) > 0 || len(cfg.Age.Recipients) > 0 {
		return envelope.ModeAge
	}
	return envelope.ModePassword
}

func chooseCandidate(opts runOptions, title string, candidates []discovery.Candidate) (discovery.Candidate, error) {
	if len(candidates) == 0 {
		return discovery.Candidate{}, fmt.Errorf("no candidate files found")
	}
	labels := make([]string, 0, len(candidates))
	byLabel := make(map[string]discovery.Candidate, len(candidates))
	for _, candidate := range candidates {
		label := candidate.Path
		labels = append(labels, label)
		byLabel[label] = candidate
	}
	choice, err := chooseString(opts, title, labels)
	if err != nil {
		return discovery.Candidate{}, err
	}
	return byLabel[choice], nil
}

func chooseString(opts runOptions, title string, options []string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("no options available")
	}
	fmt.Fprintln(opts.stdout, title)
	for idx, option := range options {
		fmt.Fprintf(opts.stdout, "  %d. %s\n", idx+1, option)
	}
	response, err := prompt(opts, "Select option: ")
	if err != nil {
		return "", err
	}
	if response == "" {
		return options[0], nil
	}
	idx := 0
	if _, err := fmt.Sscanf(response, "%d", &idx); err != nil || idx < 1 || idx > len(options) {
		return "", fmt.Errorf("invalid selection %q", response)
	}
	return options[idx-1], nil
}

func prompt(opts runOptions, label string) (string, error) {
	fmt.Fprint(opts.stdout, label)
	text, err := getReader(opts).ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return strings.TrimSpace(text), nil
		}
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func promptSecret(opts runOptions, label string) (string, error) {
	if file, ok := opts.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(opts.stdout, label)
		secret, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(opts.stdout)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(secret)), nil
	}
	return prompt(opts, label)
}

func getReader(opts runOptions) *bufio.Reader {
	if opts.reader != nil {
		return opts.reader
	}
	if opts.stdin == nil {
		return bufio.NewReader(strings.NewReader(""))
	}
	return bufio.NewReader(opts.stdin)
}

func loadConfig(cwd string) (config.Config, configSource, error) {
	source, err := resolveConfigSource(cwd)
	if err != nil {
		return config.Config{}, configSource{}, err
	}
	if source.Exists {
		cfg, err := config.Load(source.Path)
		return cfg, source, err
	}
	return config.Default(), source, nil
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s %s\n", appName, version)
}

func resolveConfigSource(cwd string) (configSource, error) {
	primaryPath := filepath.Join(cwd, primaryConfig)
	if _, err := os.Stat(primaryPath); err == nil {
		return configSource{Path: primaryPath, Exists: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return configSource{}, err
	}

	legacyPath := filepath.Join(cwd, legacyConfig)
	if _, err := os.Stat(legacyPath); err == nil {
		return configSource{Path: legacyPath, Exists: true, Legacy: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return configSource{}, err
	}

	return configSource{Path: primaryPath}, nil
}

func collectDoctorReport(cwd string) (doctorReport, error) {
	source, err := resolveConfigSource(cwd)
	if err != nil {
		return doctorReport{}, err
	}
	report := doctorReport{Config: source}

	cfg := config.Default()
	if source.Exists {
		loaded, err := config.Load(source.Path)
		if err != nil {
			report.ConfigError = err
		} else {
			cfg = loaded
		}
	}

	report.RecipientCount = len(cfg.Age.Recipients)
	report.KeyPath = expandHome(cfg.KeyFile)
	if _, err := os.Stat(report.KeyPath); err == nil {
		report.KeyExists = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return doctorReport{}, err
	} else if cfg.KeyFile == config.DefaultKeyFile {
		legacyPath := expandHome(config.LegacyKeyFile)
		if _, legacyErr := os.Stat(legacyPath); legacyErr == nil {
			report.KeyPath = legacyPath
			report.KeyExists = true
			report.KeyUsesLegacy = true
		} else if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
			return doctorReport{}, legacyErr
		}
	}

	candidates, err := discovery.FindCandidates(cwd)
	if err != nil {
		return doctorReport{}, err
	}
	report.SuggestedFiles = len(candidates)

	encryptedFiles, err := findEncryptedFiles(cwd)
	if err != nil {
		return doctorReport{}, err
	}
	report.EncryptedFiles = len(encryptedFiles)
	return report, nil
}

func printDoctorReport(w io.Writer, report doctorReport) {
	fmt.Fprintln(w, doctorTitle)
	fmt.Fprintln(w)

	switch {
	case report.ConfigError != nil:
		fmt.Fprintf(w, "Config: ERROR (%s)\n", report.Config.Path)
		fmt.Fprintf(w, "Config Error: %v\n", report.ConfigError)
	case report.Config.Exists && report.Config.Legacy:
		fmt.Fprintf(w, "Config: OK (%s, %s)\n", report.Config.Path, legacyDoctorNote)
	case report.Config.Exists:
		fmt.Fprintf(w, "Config: OK (%s)\n", report.Config.Path)
	default:
		fmt.Fprintf(w, "Config: MISSING (%s)\n", report.Config.Path)
	}

	switch {
	case report.KeyExists && report.KeyUsesLegacy:
		fmt.Fprintf(w, "Key File: OK (%s, legacy fallback)\n", report.KeyPath)
	case report.KeyExists:
		fmt.Fprintf(w, "Key File: OK (%s)\n", report.KeyPath)
	default:
		fmt.Fprintf(w, "Key File: MISSING (%s)\n", report.KeyPath)
	}

	fmt.Fprintf(w, "Recipients: %d\n", report.RecipientCount)
	fmt.Fprintf(w, "Suggested Files: %d\n", report.SuggestedFiles)
	fmt.Fprintf(w, "Encrypted Files: %d\n", report.EncryptedFiles)
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
	return files, nil
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

type encryptArgs struct {
	filePath       string
	outPath        string
	passwordText   string
	recipientsText string
	useAge         bool
}

func parseEncryptArgs(args []string) (encryptArgs, error) {
	var parsed encryptArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--out":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --out")
			}
			parsed.outPath = args[i]
		case "--password":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --password")
			}
			parsed.passwordText = args[i]
		case "--recipient":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --recipient")
			}
			parsed.recipientsText = args[i]
		case "--age":
			parsed.useAge = true
		default:
			if strings.HasPrefix(arg, "--") {
				return parsed, fmt.Errorf("unknown flag %q", arg)
			}
			if parsed.filePath == "" {
				parsed.filePath = arg
				continue
			}
			return parsed, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	return parsed, nil
}

type decryptArgs struct {
	filePath     string
	outPath      string
	passwordText string
	identityPath string
}

func parseDecryptArgs(args []string) (decryptArgs, error) {
	var parsed decryptArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--out":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --out")
			}
			parsed.outPath = args[i]
		case "--password":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --password")
			}
			parsed.passwordText = args[i]
		case "--identity":
			i++
			if i >= len(args) {
				return parsed, fmt.Errorf("missing value for --identity")
			}
			parsed.identityPath = args[i]
		default:
			if strings.HasPrefix(arg, "--") {
				return parsed, fmt.Errorf("unknown flag %q", arg)
			}
			if parsed.filePath == "" {
				parsed.filePath = arg
				continue
			}
			return parsed, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	return parsed, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s %s\n", appName, version)
	fmt.Fprintf(w, "%s <command> [flags]\n", appName)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  init")
	fmt.Fprintln(w, "  keygen")
	fmt.Fprintln(w, "  encrypt")
	fmt.Fprintln(w, "  decrypt")
	fmt.Fprintln(w, "  inspect")
	fmt.Fprintln(w, "  tui")
	fmt.Fprintln(w, "  doctor")
	fmt.Fprintln(w, "  version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --version, -v")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func padRight(text string, width int) string {
	if len(text) >= width {
		return truncate(text, width)
	}
	return text + strings.Repeat(" ", width-len(text))
}

func truncate(text string, width int) string {
	if len(text) <= width {
		return text
	}
	if width <= 1 {
		return text[:width]
	}
	return text[:width-1] + "…"
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}
