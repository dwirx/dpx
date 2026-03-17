package tui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"dopx/internal/app"
	"dopx/internal/config"
	"dopx/internal/discovery"
	"dopx/internal/envelope"
)

func RunFallback(svc app.Service, cfg config.Config, cwd string, stdin io.Reader, stdout io.Writer) error {
	reader := bufio.NewReader(stdin)
	renderHeader(stdout)

	action, err := chooseString(reader, stdout, "Choose an action", []string{"Encrypt", "Decrypt", "Inspect"})
	if err != nil {
		return err
	}

	switch action {
	case "Encrypt":
		candidates, err := svc.Discover(cwd)
		if err != nil {
			return err
		}
		candidate, err := chooseCandidate(reader, stdout, "Select a file to encrypt", candidates)
		if err != nil {
			return err
		}
		mode, err := chooseString(reader, stdout, "Choose encryption mode", []string{"Age", "Password"})
		if err != nil {
			return err
		}
		req := app.EncryptRequest{InputPath: candidate.Path}
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
			pass, err := prompt(reader, stdout, "Password: ")
			if err != nil {
				return err
			}
			req.Passphrase = []byte(pass)
		}
		out, err := prompt(reader, stdout, fmt.Sprintf("Output path [%s]: ", candidate.Path+cfg.DefaultSuffix))
		if err != nil {
			return err
		}
		req.OutputPath = strings.TrimSpace(out)
		outputPath, err := svc.EncryptFile(req)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Encrypted %s -> %s\n", candidate.Path, outputPath)
		return nil
	case "Decrypt":
		files, err := findEncryptedFiles(cwd)
		if err != nil {
			return err
		}
		filePath, err := chooseString(reader, stdout, "Select a file to decrypt", files)
		if err != nil {
			return err
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
		filePath, err := chooseString(reader, stdout, "Select a file to inspect", files)
		if err != nil {
			return err
		}
		meta, err := svc.Inspect(filePath)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Version: %d\nMode: %s\nOriginal Name: %s\nCreated At: %s\n", meta.Version, meta.Mode, meta.OriginalName, meta.CreatedAt.Format("2006-01-02 15:04:05Z07:00"))
		return nil
	default:
		return fmt.Errorf("unsupported action %q", action)
	}
}

func renderHeader(w io.Writer) {
	fmt.Fprintln(w, "╭──────────────────────────────────────────────────────────────╮")
	fmt.Fprintln(w, "│ DPX TUI                                                      │")
	fmt.Fprintln(w, "│ Full-screen secrets workflow for encrypt, decrypt, inspect   │")
	fmt.Fprintln(w, "╰──────────────────────────────────────────────────────────────╯")
}

func chooseCandidate(reader *bufio.Reader, stdout io.Writer, title string, candidates []discovery.Candidate) (discovery.Candidate, error) {
	if len(candidates) == 0 {
		return discovery.Candidate{}, fmt.Errorf("no candidate files found")
	}
	labels := make([]string, 0, len(candidates))
	index := make(map[string]discovery.Candidate, len(candidates))
	for _, candidate := range candidates {
		labels = append(labels, candidate.Path)
		index[candidate.Path] = candidate
	}
	choice, err := chooseString(reader, stdout, title, labels)
	if err != nil {
		return discovery.Candidate{}, err
	}
	return index[choice], nil
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
