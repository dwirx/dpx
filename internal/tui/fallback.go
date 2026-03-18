package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/crypto/password"
	"github.com/dwirx/dpx/internal/discovery"
	"github.com/dwirx/dpx/internal/envelope"
	"github.com/dwirx/dpx/internal/policy"
	"github.com/dwirx/dpx/internal/safeio"
)

func RunFallback(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) error {
	reader := bufio.NewReader(stdin)
	renderHeader(stdout)

	action, err := chooseString(reader, stdout, "Choose an action", []string{"Encrypt", "Decrypt", "Inspect", "Auto", "Import Key", "Doctor", "Env Inline Encrypt", "Env Inline Decrypt", "Env Set", "Env Update Keys", "Policy Check"})
	if err != nil {
		return err
	}

	switch action {
	case "Encrypt":
		inputPath, err := chooseEncryptPathFallback(reader, stdout, svc, cwd)
		if err != nil {
			return err
		}
		mode, err := chooseString(reader, stdout, "Choose encryption mode", []string{"Age", "Password"})
		if err != nil {
			return err
		}
		req := app.EncryptRequest{InputPath: inputPath}
		if mode == "Age" {
			req.Mode = envelope.ModeAge
			if len(cfg.Age.Recipients) > 0 {
				req.Recipients = append([]string{}, cfg.Age.Recipients...)
			} else {
				text, err := prompt(reader, stdout, "Recipients (comma-separated): ")
				if err != nil {
					return err
				}
				req.Recipients = splitCSV(text)
			}
		} else {
			req.Mode = envelope.ModePassword
			req.KDFProfile = password.KDFProfileHardened
			passphrase, err := promptPasswordWithConfirmation(reader, stdout)
			if err != nil {
				return err
			}
			req.Passphrase = passphrase
		}
		out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", req.InputPath+cfg.DefaultSuffix))
		if err != nil {
			return err
		}
		req.OutputPath = strings.TrimSpace(out)
		outputPath, err := svc.EncryptFile(req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Encrypted %s -> %s\n", req.InputPath, outputPath)
		return nil
	case "Decrypt":
		files, err := findEncryptedFiles(cwd)
		if err != nil {
			return err
		}
		filePath := ""
		if len(files) == 0 {
			fmt.Fprintln(stdout, "No .dpx files found in current directory.")
			filePath, err = prompt(reader, stdout, "File to decrypt (.dpx): ")
			if err != nil {
				return err
			}
			if strings.TrimSpace(filePath) == "" {
				return fmt.Errorf("file path is required")
			}
		} else {
			filePath, err = chooseString(reader, stdout, "Select a file to decrypt", files)
			if err != nil {
				return err
			}
		}
		meta, err := svc.Inspect(filePath)
		if err != nil {
			return err
		}
		req := app.DecryptRequest{InputPath: filePath}
		if meta.Mode == envelope.ModePassword {
			pass, err := prompt(reader, stdout, "Password: ")
			if err != nil {
				return err
			}
			req.Passphrase = []byte(pass)
		}
		out, err := prompt(reader, stdout, "Output path [default]: ")
		if err != nil {
			return err
		}
		req.OutputPath = strings.TrimSpace(out)
		outputPath, err := svc.DecryptFile(req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Decrypted %s -> %s\n", filePath, outputPath)
		return nil
	case "Inspect":
		files, err := findEncryptedFiles(cwd)
		if err != nil {
			return err
		}
		filePath := ""
		if len(files) == 0 {
			fmt.Fprintln(stdout, "No .dpx files found in current directory.")
			filePath, err = prompt(reader, stdout, "File to inspect (.dpx): ")
			if err != nil {
				return err
			}
			if strings.TrimSpace(filePath) == "" {
				return fmt.Errorf("file path is required")
			}
		} else {
			filePath, err = chooseString(reader, stdout, "Select a file to inspect", files)
			if err != nil {
				return err
			}
		}
		meta, err := svc.Inspect(filePath)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Version: %d\nMode: %s\nOriginal Name: %s\nCreated At: %s\n", meta.Version, meta.Mode, meta.OriginalName, meta.CreatedAt.Format("2006-01-02 15:04:05Z07:00"))
		return nil
	case "Auto":
		filePath, err := prompt(reader, stdout, "File path (any file or .dpx): ")
		if err != nil {
			return err
		}
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			return fmt.Errorf("file path is required")
		}
		if isEncryptedPath(filePath, cfg.DefaultSuffix) {
			meta, err := svc.Inspect(filePath)
			if err != nil {
				return err
			}
			req := app.DecryptRequest{InputPath: filePath}
			if meta.Mode == envelope.ModePassword {
				pass, err := prompt(reader, stdout, "Password: ")
				if err != nil {
					return err
				}
				req.Passphrase = []byte(pass)
			}
			out, err := prompt(reader, stdout, "Output path [default]: ")
			if err != nil {
				return err
			}
			req.OutputPath = strings.TrimSpace(out)
			outputPath, err := svc.DecryptFile(req)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Decrypted %s -> %s\n", filePath, outputPath)
			return nil
		}
		req := app.EncryptRequest{InputPath: filePath, Mode: envelope.ModePassword}
		req.KDFProfile = password.KDFProfileHardened
		passphrase, err := promptPasswordWithConfirmation(reader, stdout)
		if err != nil {
			return err
		}
		req.Passphrase = passphrase
		out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", req.InputPath+cfg.DefaultSuffix))
		if err != nil {
			return err
		}
		req.OutputPath = strings.TrimSpace(out)
		outputPath, err := svc.EncryptFile(req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Encrypted %s -> %s\n", req.InputPath, outputPath)
		return nil
	case "Env Inline Encrypt":
		return runEnvInlineEncryptFallback(reader, stdout, svc, cfg, cwd)
	case "Env Inline Decrypt":
		return runEnvInlineDecryptFallback(reader, stdout, svc, cfg, cwd)
	case "Env Set":
		return runEnvSetFallback(reader, stdout, svc, cfg, cwd)
	case "Env Update Keys":
		return runEnvUpdateKeysFallback(reader, stdout, svc, cfg, cwd)
	case "Policy Check":
		return runPolicyCheckFallback(reader, stdout, svc, cwd)
	case "Import Key":
		source, err := chooseString(reader, stdout, "Import source", []string{"From file", "Paste key block"})
		if err != nil {
			return err
		}
		raw := ""
		if source == "From file" {
			path, err := prompt(reader, stdout, "Path to age key file: ")
			if err != nil {
				return err
			}
			path = strings.TrimSpace(path)
			if path == "" {
				return fmt.Errorf("import file path is required")
			}
			data, err := os.ReadFile(expandHome(path))
			if err != nil {
				return err
			}
			raw = string(data)
		} else {
			raw, err = promptAgeKeyBlock(reader, stdout, "Paste key block")
			if err != nil {
				return err
			}
		}
		if extractAgeSecretKey(raw) == "" {
			return fmt.Errorf("no AGE-SECRET-KEY found in input")
		}
		out, err := prompt(reader, stdout, fmt.Sprintf("Output key path [%s]: ", cfg.KeyFile))
		if err != nil {
			return err
		}
		message, err := importIdentityAndSyncConfig(svc, cwd, cfg, strings.TrimSpace(out), raw)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, message)
		return nil
	case "Doctor":
		report, err := collectDoctorReportForTUI(svc, cwd, cfg)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, formatDoctorReport(report))
		return nil
	default:
		return fmt.Errorf("unsupported action %q", action)
	}
}

func renderHeader(w io.Writer) {
	fmt.Fprintln(w, "╭──────────────────────────────────────────────────────────────╮")
	fmt.Fprintln(w, "│ DPX TUI                                                      │")
	fmt.Fprintln(w, "│ Encrypt/decrypt/inspect/env/policy/import/doctor workflow    │")
	fmt.Fprintln(w, "╰──────────────────────────────────────────────────────────────╯")
}

func runEnvSetFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cfg config.Config, cwd string) error {
	candidates, err := svc.Discover(cwd)
	if err != nil {
		return err
	}
	options := candidateLabels(candidates)
	options = append(options, manualEncryptPathOption)
	inputPath, err := chooseString(reader, stdout, "Select a .env file for env set", options)
	if err != nil {
		return err
	}
	if inputPath == manualEncryptPathOption {
		inputPath, err = prompt(reader, stdout, "Env file path: ")
		if err != nil {
			return err
		}
		inputPath = strings.TrimSpace(inputPath)
		if inputPath == "" {
			return fmt.Errorf("file path is required")
		}
	}

	key, err := prompt(reader, stdout, "Key name: ")
	if err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("key name is required")
	}

	value, err := prompt(reader, stdout, "Value: ")
	if err != nil {
		return err
	}

	mode, err := chooseString(reader, stdout, "Set mode", []string{"Plaintext", "Encrypt (Age)", "Encrypt (Password)"})
	if err != nil {
		return err
	}

	req := app.EnvInlineSetRequest{
		InputPath: inputPath,
		Key:       key,
		Value:     value,
	}
	switch mode {
	case "Encrypt (Age)":
		req.Encrypt = true
		req.Mode = envelope.ModeAge
		req.Recipients = append([]string{}, cfg.Age.Recipients...)
		if len(req.Recipients) == 0 {
			text, err := prompt(reader, stdout, "Recipients (comma-separated): ")
			if err != nil {
				return err
			}
			req.Recipients = splitCSV(text)
		}
	case "Encrypt (Password)":
		req.Encrypt = true
		req.Mode = envelope.ModePassword
		req.KDFProfile = password.KDFProfileHardened
		passphrase, err := promptPasswordWithConfirmation(reader, stdout)
		if err != nil {
			return err
		}
		req.Passphrase = passphrase
	default:
		req.Encrypt = false
	}

	out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", req.InputPath))
	if err != nil {
		return err
	}
	req.OutputPath = strings.TrimSpace(out)
	result, err := svc.SetEnvInlineValue(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Env value updated in %s\n", req.InputPath)
	fmt.Fprintf(stdout, "Output: %s\n", result.OutputPath)
	fmt.Fprintf(stdout, "Updated keys (%d): %s\n", len(result.Updated), strings.Join(result.Updated, ", "))
	return nil
}

func runEnvUpdateKeysFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cfg config.Config, cwd string) error {
	files, err := findEncryptedFiles(cwd)
	if err != nil {
		return err
	}
	options := append([]string{}, files...)
	options = append(options, manualEncryptPathOption)
	filePath, err := chooseString(reader, stdout, "Select a .env.dpx file to rotate recipients", options)
	if err != nil {
		return err
	}
	if filePath == manualEncryptPathOption {
		filePath, err = prompt(reader, stdout, "Env .dpx file path: ")
		if err != nil {
			return err
		}
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			return fmt.Errorf("file path is required")
		}
	}

	recipientsText, err := prompt(reader, stdout, "Recipients (comma-separated): ")
	if err != nil {
		return err
	}
	recipients := splitCSV(recipientsText)
	if len(recipients) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}

	keys, err := svc.ListEnvInlineAgeEncryptedKeys(filePath)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no age-encrypted keys found")
	}
	selectedKeys, err := chooseEnvKeysFallback(reader, stdout, keys)
	if err != nil {
		return err
	}

	req := app.EnvInlineUpdateRecipientsRequest{
		InputPath:    filePath,
		IdentityPath: cfg.KeyFile,
		Recipients:   recipients,
		SelectedKeys: selectedKeys,
	}
	out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", req.InputPath))
	if err != nil {
		return err
	}
	req.OutputPath = strings.TrimSpace(out)
	result, err := svc.UpdateEnvInlineRecipients(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Recipients updated in %s\n", req.InputPath)
	fmt.Fprintf(stdout, "Output: %s\n", result.OutputPath)
	fmt.Fprintf(stdout, "Updated keys (%d): %s\n", len(result.Updated), strings.Join(result.Updated, ", "))
	return nil
}

func runPolicyCheckFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cwd string) error {
	candidates, err := svc.DiscoverEncryptTargets(cwd)
	if err != nil {
		return err
	}
	options := candidateLabels(candidates)
	options = append(options, manualEncryptPathOption)
	filePath, err := chooseString(reader, stdout, "Select a file for policy check", options)
	if err != nil {
		return err
	}
	if filePath == manualEncryptPathOption {
		filePath, err = prompt(reader, stdout, "File path: ")
		if err != nil {
			return err
		}
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			return fmt.Errorf("file path is required")
		}
	}

	data, err := safeio.ReadFile(filePath)
	if err != nil {
		return err
	}
	report := policy.Check(filePath, data)
	if report.SkipReason != "" {
		fmt.Fprintf(stdout, "Policy OK (%s)\n", report.SkipReason)
		return nil
	}
	if len(report.Findings) == 0 {
		fmt.Fprintf(stdout, "Policy OK: no plaintext sensitive keys found (%s)\n", report.Format)
		return nil
	}
	fmt.Fprintf(stdout, "Policy findings: %d (%s)\n", len(report.Findings), report.Format)
	for _, finding := range report.Findings {
		if finding.Line > 0 {
			fmt.Fprintf(stdout, "- line %d key=%s: %s\n", finding.Line, finding.Key, finding.Reason)
		} else {
			fmt.Fprintf(stdout, "- key=%s: %s\n", finding.Key, finding.Reason)
		}
	}
	return nil
}

func runEnvInlineEncryptFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cfg config.Config, cwd string) error {
	inputPath, err := chooseEncryptPathFallback(reader, stdout, svc, cwd)
	if err != nil {
		return err
	}
	mode, err := chooseString(reader, stdout, "Choose inline env encryption mode", []string{"Age", "Password"})
	if err != nil {
		return err
	}
	keys, err := svc.ListEnvInlineKeys(inputPath)
	if err != nil {
		return err
	}
	selectedKeys, err := chooseEnvKeysFallback(reader, stdout, keys)
	if err != nil {
		return err
	}

	req := app.EnvInlineEncryptRequest{
		InputPath:    inputPath,
		SelectedKeys: selectedKeys,
	}
	if mode == "Age" {
		req.Mode = envelope.ModeAge
		req.Recipients = append([]string{}, cfg.Age.Recipients...)
		if len(req.Recipients) == 0 {
			text, err := prompt(reader, stdout, "Recipients (comma-separated): ")
			if err != nil {
				return err
			}
			req.Recipients = splitCSV(text)
		}
	} else {
		req.Mode = envelope.ModePassword
		req.KDFProfile = password.KDFProfileHardened
		passphrase, err := promptPasswordWithConfirmation(reader, stdout)
		if err != nil {
			return err
		}
		req.Passphrase = passphrase
	}

	out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", req.InputPath+cfg.DefaultSuffix))
	if err != nil {
		return err
	}
	req.OutputPath = strings.TrimSpace(out)
	result, err := svc.EncryptEnvInlineFile(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Env inline encrypted %s -> %s\n", req.InputPath, result.OutputPath)
	fmt.Fprintf(stdout, "Updated keys (%d): %s\n", len(result.Updated), strings.Join(result.Updated, ", "))
	return nil
}

func runEnvInlineDecryptFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cfg config.Config, cwd string) error {
	files, err := findEncryptedFiles(cwd)
	if err != nil {
		return err
	}
	filePath := ""
	if len(files) == 0 {
		filePath, err = prompt(reader, stdout, "Env .dpx file path: ")
		if err != nil {
			return err
		}
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			return fmt.Errorf("file path is required")
		}
	} else {
		filePath, err = chooseString(reader, stdout, "Select a .env.dpx file to decrypt", files)
		if err != nil {
			return err
		}
	}

	hasAge, hasPassword, err := svc.DetectEnvInlineModes(filePath)
	if err != nil {
		return err
	}
	req := app.EnvInlineDecryptRequest{
		InputPath:    filePath,
		IdentityPath: cfg.KeyFile,
	}
	if hasPassword {
		pass, err := promptPasswordWithConfirmation(reader, stdout)
		if err != nil {
			return err
		}
		req.Passphrase = pass
	}
	if !hasAge {
		req.IdentityPath = ""
	}
	out, err := prompt(reader, stdout, "Output path [default]: ")
	if err != nil {
		return err
	}
	req.OutputPath = strings.TrimSpace(out)
	result, err := svc.DecryptEnvInlineFile(req)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Env inline decrypted %s -> %s\n", req.InputPath, result.OutputPath)
	fmt.Fprintf(stdout, "Updated keys (%d): %s\n", len(result.Updated), strings.Join(result.Updated, ", "))
	return nil
}

func chooseEnvKeysFallback(reader *bufio.Reader, stdout io.Writer, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no encryptable env keys found")
	}
	fmt.Fprintln(stdout, "Select keys to encrypt:")
	for i, key := range keys {
		fmt.Fprintf(stdout, "  %d. %s\n", i+1, key)
	}
	raw, err := prompt(reader, stdout, `Keys (comma-separated indexes or "all"): `)
	if err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "all" {
		return append([]string{}, keys...), nil
	}

	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{})
	selected := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		index, convErr := strconv.Atoi(part)
		if convErr != nil || index < 1 || index > len(keys) {
			return nil, fmt.Errorf("invalid key index %q", part)
		}
		key := keys[index-1]
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, key)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no keys selected")
	}
	return selected, nil
}

func chooseEncryptPathFallback(reader *bufio.Reader, stdout io.Writer, svc app.Service, cwd string) (string, error) {
	scope := encryptScopeAny
	for {
		candidates, err := discoverEncryptCandidatesByScopeFallback(svc, cwd, scope)
		if err != nil {
			return "", err
		}
		options := candidateLabels(candidates)
		options = append(options, manualEncryptPathOption)
		if len(candidates) > 0 {
			options = append(options, searchEncryptPathOption)
		}
		options = append(options, encryptScopeSwitchOption(scope))
		choice, err := chooseString(reader, stdout, encryptScopeTitle(scope), options)
		if err != nil {
			return "", err
		}
		switch choice {
		case manualEncryptPathOption:
			path, err := prompt(reader, stdout, "File to encrypt: ")
			if err != nil {
				return "", err
			}
			path = strings.TrimSpace(path)
			if path == "" {
				return "", fmt.Errorf("file path is required")
			}
			return path, nil
		case searchEncryptPathOption:
			if len(candidates) == 0 {
				fmt.Fprintln(stdout, "No files available to search in this mode.")
				continue
			}
			query, err := prompt(reader, stdout, "Search keyword: ")
			if err != nil {
				return "", err
			}
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}
			filtered := filterPathsByQuery(candidateLabels(candidates), query)
			if len(filtered) == 0 {
				fmt.Fprintf(stdout, "No files match %q in %s mode.\n", query, encryptScopeName(scope))
				continue
			}
			if len(filtered) == 1 {
				return filtered[0], nil
			}
			picked, err := chooseString(reader, stdout, fmt.Sprintf("Search results for %q", query), append(filtered, "[back] Back"))
			if err != nil {
				return "", err
			}
			if picked == "[back] Back" {
				continue
			}
			return picked, nil
		case encryptScopeSwitchOption(scope):
			scope = toggleEncryptScope(scope)
			continue
		default:
			return choice, nil
		}
	}
}

func discoverEncryptCandidatesByScopeFallback(svc app.Service, cwd string, scope encryptScope) ([]discovery.Candidate, error) {
	switch scope {
	case encryptScopeEnv:
		return svc.Discover(cwd)
	default:
		return svc.DiscoverEncryptTargets(cwd)
	}
}

func chooseString(reader *bufio.Reader, stdout io.Writer, title string, options []string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("no options available")
	}
	fmt.Fprintln(stdout, title)
	for idx, option := range options {
		fmt.Fprintf(stdout, "  %d. %s\n", idx+1, option)
	}
	text, err := prompt(reader, stdout, "Select option: ")
	if err != nil {
		return "", err
	}
	if text == "" {
		return options[0], nil
	}
	selected := 0
	if _, err := fmt.Sscanf(text, "%d", &selected); err != nil || selected < 1 || selected > len(options) {
		return "", fmt.Errorf("invalid selection %q", text)
	}
	return options[selected-1], nil
}

func prompt(reader *bufio.Reader, stdout io.Writer, label string) (string, error) {
	fmt.Fprint(stdout, label)
	text, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func promptMultiline(reader *bufio.Reader, stdout io.Writer, label, terminator string) (string, error) {
	fmt.Fprintf(stdout, "%s (finish with %s on a new line):\n", label, terminator)
	lines := make([]string, 0, 8)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == terminator {
			break
		}
		lines = append(lines, trimmed)
		if err == io.EOF {
			break
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}

func promptAgeKeyBlock(reader *bufio.Reader, stdout io.Writer, label string) (string, error) {
	fmt.Fprintf(stdout, "%s (paste age-keys block; auto-stop at AGE-SECRET-KEY line or END):\n", label)
	lines := make([]string, 0, 8)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		token := strings.TrimSpace(trimmed)
		if token == "END" {
			break
		}
		lines = append(lines, trimmed)
		if strings.HasPrefix(token, "AGE-SECRET-KEY-") {
			break
		}
		if err == io.EOF {
			break
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), nil
}

func promptPasswordWithConfirmation(reader *bufio.Reader, stdout io.Writer) ([]byte, error) {
	for {
		pass, err := prompt(reader, stdout, "Password: ")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(pass) == "" {
			return nil, fmt.Errorf("password is required")
		}
		confirm, err := prompt(reader, stdout, "Confirm password: ")
		if err != nil {
			return nil, err
		}
		if pass == confirm {
			return []byte(pass), nil
		}
		fmt.Fprintln(stdout, "Password confirmation does not match. Try again.")
	}
}
