package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/crypto/password"
	"github.com/dwirx/dpx/internal/envelope"
)

const (
	defaultGeneratedPasswordLength = 28
	minGeneratedPasswordLength     = 16
	maxGeneratedPasswordLength     = 128
	manualRepasswordPathOption     = "[manual] Enter custom file path"
)

const (
	passwordLower   = "abcdefghijkmnopqrstuvwxyz"
	passwordUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	passwordDigits  = "23456789"
	passwordSymbols = "!@#$%^&*()-_=+"
)

type repasswordArgs struct {
	filePath        string
	outPath         string
	oldPasswordText string
	newPasswordText string
	generate        bool
	passwordLength  int
	kdfProfile      string
}

func parseRepasswordArgs(args []string, opts runOptions) (repasswordArgs, error) {
	fs := flag.NewFlagSet("repassword", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	oldPassword := fs.String("old-password", "", "current password (prompt if empty)")
	newPassword := fs.String("new-password", "", "new password (prompt if empty)")
	generate := fs.Bool("generate-password", false, "generate a secure new password")
	passwordLength := fs.Int("password-length", defaultGeneratedPasswordLength, "length for generated password")
	kdfProfile := fs.String("kdf-profile", password.KDFProfileHardened, "kdf profile: balanced|hardened|paranoid")
	outPath := fs.String("out", "", "output path (default: overwrite input)")
	if err := fs.Parse(args); err != nil {
		return repasswordArgs{}, err
	}
	if fs.NArg() > 1 {
		return repasswordArgs{}, fmt.Errorf("unexpected argument %q", fs.Arg(1))
	}

	normalizedProfile := password.NormalizeProfile(*kdfProfile)
	switch normalizedProfile {
	case password.KDFProfileBalanced, password.KDFProfileHardened, password.KDFProfileParanoid:
	default:
		return repasswordArgs{}, fmt.Errorf("unsupported kdf profile %q (supported: %s, %s, %s)", *kdfProfile, password.KDFProfileBalanced, password.KDFProfileHardened, password.KDFProfileParanoid)
	}
	if *generate && strings.TrimSpace(*newPassword) != "" {
		return repasswordArgs{}, fmt.Errorf("use either --new-password or --generate-password, not both")
	}
	if *passwordLength < minGeneratedPasswordLength || *passwordLength > maxGeneratedPasswordLength {
		return repasswordArgs{}, fmt.Errorf("password length must be between %d and %d", minGeneratedPasswordLength, maxGeneratedPasswordLength)
	}

	parsed := repasswordArgs{
		outPath:         strings.TrimSpace(*outPath),
		oldPasswordText: *oldPassword,
		newPasswordText: *newPassword,
		generate:        *generate,
		passwordLength:  *passwordLength,
		kdfProfile:      normalizedProfile,
	}
	if fs.NArg() == 1 {
		parsed.filePath = strings.TrimSpace(fs.Arg(0))
	}
	return parsed, nil
}

func runRepassword(svc app.Service, args []string, opts runOptions) error {
	parsed, err := parseRepasswordArgs(args, opts)
	if err != nil {
		return err
	}

	filePath := parsed.filePath
	if filePath == "" {
		files, err := findEncryptedFiles(opts.cwd)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			path, err := prompt(opts, "File to update password (.dpx or inline env): ")
			if err != nil {
				return err
			}
			path = strings.TrimSpace(path)
			if path == "" {
				return fmt.Errorf("file path is required")
			}
			filePath = path
		} else {
			options := append([]string{}, files...)
			options = append(options, manualRepasswordPathOption)
			choice, err := chooseString(opts, "Select a file to update password", options)
			if err != nil {
				return err
			}
			if choice == manualRepasswordPathOption {
				path, err := prompt(opts, "File to update password (.dpx or inline env): ")
				if err != nil {
					return err
				}
				path = strings.TrimSpace(path)
				if path == "" {
					return fmt.Errorf("file path is required")
				}
				filePath = path
			} else {
				filePath = choice
			}
		}
	}

	oldPassword := parsed.oldPasswordText
	if strings.TrimSpace(oldPassword) == "" {
		oldPassword, err = promptSecret(opts, "Current password: ")
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(oldPassword) == "" {
		return fmt.Errorf("current password is required")
	}

	newPassword := parsed.newPasswordText
	generated := false
	if parsed.generate {
		newPassword, err = generateStrongPassword(parsed.passwordLength)
		if err != nil {
			return err
		}
		generated = true
	} else if strings.TrimSpace(newPassword) == "" {
		newPassword, err = promptSecretWithConfirmation(opts, "New password: ", "Confirm new password: ")
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(newPassword) == "" {
		return fmt.Errorf("new password is required")
	}
	if oldPassword == newPassword {
		return fmt.Errorf("new password must be different from current password")
	}

	meta, inspectErr := svc.Inspect(filePath)
	if inspectErr == nil {
		if meta.Mode != envelope.ModePassword {
			return fmt.Errorf("repassword only supports password-mode files, got mode %q", meta.Mode)
		}
		tempFile, err := os.CreateTemp(filepath.Dir(filePath), ".dpx-repassword-*")
		if err != nil {
			return err
		}
		tempPath := tempFile.Name()
		if closeErr := tempFile.Close(); closeErr != nil {
			_ = os.Remove(tempPath)
			return closeErr
		}
		defer os.Remove(tempPath)

		if _, err := svc.DecryptFile(app.DecryptRequest{
			InputPath:  filePath,
			OutputPath: tempPath,
			Passphrase: []byte(oldPassword),
		}); err != nil {
			return fmt.Errorf("failed to decrypt with current password: %w", err)
		}

		outputPath := parsed.outPath
		if outputPath == "" {
			outputPath = filePath
		}
		writtenPath, err := svc.EncryptFile(app.EncryptRequest{
			InputPath:  tempPath,
			OutputPath: outputPath,
			Mode:       envelope.ModePassword,
			Passphrase: []byte(newPassword),
			KDFProfile: parsed.kdfProfile,
			Recipients: nil,
		})
		if err != nil {
			return err
		}

		fmt.Fprintf(opts.stdout, "Password updated %s -> %s\n", filePath, writtenPath)
		if generated {
			fmt.Fprintf(opts.stdout, "Generated password: %s\n", newPassword)
		}
		return nil
	}

	hasAge, hasPassword, detectErr := svc.DetectEnvInlineModes(filePath)
	if detectErr != nil {
		return inspectErr
	}
	if hasPassword {
		result, err := svc.RepasswordEnvInlineFile(app.EnvInlineRepasswordRequest{
			InputPath:     filePath,
			OutputPath:    parsed.outPath,
			OldPassphrase: []byte(oldPassword),
			NewPassphrase: []byte(newPassword),
			KDFProfile:    parsed.kdfProfile,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(opts.stdout, "Env inline password updated %s -> %s\n", filePath, result.OutputPath)
		fmt.Fprintf(opts.stdout, "Updated keys (%d): %s\n", len(result.Updated), strings.Join(result.Updated, ", "))
		if generated {
			fmt.Fprintf(opts.stdout, "Generated password: %s\n", newPassword)
		}
		return nil
	}
	if hasAge {
		return fmt.Errorf("file contains age inline tokens only; use 'dpx env updatekeys' for age mode")
	}
	return fmt.Errorf("%w (not a DPX envelope and no inline ENC tokens found)", inspectErr)
}

func generateStrongPassword(length int) (string, error) {
	value, _, err := generateStrongPasswordWithOptions(length, true)
	return value, err
}

func generateStrongPasswordWithOptions(length int, includeSymbols bool) (string, int, error) {
	if length < minGeneratedPasswordLength || length > maxGeneratedPasswordLength {
		return "", 0, fmt.Errorf("password length must be between %d and %d", minGeneratedPasswordLength, maxGeneratedPasswordLength)
	}

	allSets := []string{passwordLower, passwordUpper, passwordDigits}
	if includeSymbols {
		allSets = append(allSets, passwordSymbols)
	}
	if length < len(allSets) {
		return "", 0, fmt.Errorf("password length must be at least %d for selected character requirements", len(allSets))
	}

	allChars := strings.Join(allSets, "")
	buf := make([]byte, 0, length)

	for _, set := range allSets {
		ch, err := randomChar(set)
		if err != nil {
			return "", 0, err
		}
		buf = append(buf, ch)
	}
	for len(buf) < length {
		ch, err := randomChar(allChars)
		if err != nil {
			return "", 0, err
		}
		buf = append(buf, ch)
	}
	if err := secureShuffle(buf); err != nil {
		return "", 0, err
	}
	return string(buf), len(allChars), nil
}

func randomChar(charset string) (byte, error) {
	idx, err := cryptoRandInt(len(charset))
	if err != nil {
		return 0, err
	}
	return charset[idx], nil
}

func secureShuffle(data []byte) error {
	for i := len(data) - 1; i > 0; i-- {
		j, err := cryptoRandInt(i + 1)
		if err != nil {
			return err
		}
		data[i], data[j] = data[j], data[i]
	}
	return nil
}

func cryptoRandInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max %d", max)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
