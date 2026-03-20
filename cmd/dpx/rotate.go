package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
	"github.com/dwirx/dpx/internal/crypto/agex"
	"github.com/dwirx/dpx/internal/envelope"
)

func runRotate(svc app.Service, cfg config.Config, args []string, opts runOptions) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*yes {
		fmt.Fprintln(opts.stdout, "\n⚠️  WARNING: You are about to rotate your encryption keys.")
		fmt.Fprintln(opts.stdout, "This is a DESTRUCTIVE operation that modifies multiple files.")
		fmt.Fprintln(opts.stdout, "\nWhat this will do:")
		fmt.Fprintln(opts.stdout, "  1. Generate a ✨ NEW ✨ age key pair in memory.")
		fmt.Fprintln(opts.stdout, "  2. DECRYPT all .dpx files and inline secrets using your CURRENT key.")
		fmt.Fprintln(opts.stdout, "  3. RE-ENCRYPT everything magically with the NEW key.")
		fmt.Fprintln(opts.stdout, "  4. BACKUP your old private key to a .bak file.")
		fmt.Fprintln(opts.stdout, "  5. Update .dpx.yaml to use the new public key.")
		fmt.Fprintln(opts.stdout)
		fmt.Fprintln(opts.stdout, `Type "YES" (all caps) to confirm and start key rotation.`)
		answer, err := prompt(opts, "Confirm: ")
		if err != nil {
			return err
		}
		if answer != "YES" {
			return fmt.Errorf("rotate canceled")
		}
	}

	// 1. Read old key
	oldIdentity, err := svc.ReadIdentity(expandHome(cfg.KeyFile))
	if err != nil {
		return fmt.Errorf("failed to read current key: %w", err)
	}

	// 2. Generate new key in memory
	newIdentity, err := agex.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// Find files
	encryptedFiles, err := findEncryptedFiles(opts.cwd)
	if err != nil {
		return err
	}
	candidates, err := svc.Discover(opts.cwd)
	if err != nil {
		return err
	}

	var rotatedCount int

	// Rotate .dpx files
	for _, f := range encryptedFiles {
		meta, err := svc.Inspect(f)
		if err != nil {
			continue
		}
		if meta.Mode != envelope.ModeAge {
			continue
		}

		// Decrypt to temp file
		tempPath := f + ".tmpdecrotate"
		_, err = svc.DecryptFile(app.DecryptRequest{
			InputPath:  f,
			OutputPath: tempPath,
			PrivateKey: oldIdentity.PrivateKey,
		})
		if err != nil {
			return fmt.Errorf("failed to decrypt %s: %w", f, err)
		}

		// Re-encrypt
		_, err = svc.EncryptFile(app.EncryptRequest{
			InputPath:  tempPath,
			OutputPath: f,
			Mode:       envelope.ModeAge,
			Recipients: []string{newIdentity.PublicKey},
		})

		// Cleanup temp
		_ = os.Remove(tempPath)

		if err != nil {
			return fmt.Errorf("failed to re-encrypt %s: %w", f, err)
		}
		rotatedCount++
		fmt.Fprintf(opts.stdout, "Rotated file: %s\n", f)
	}

	// Rotate inline secrets
	for _, c := range candidates {
		hasAge, _, err := svc.DetectEnvInlineModes(c.Path)
		if err != nil || !hasAge {
			continue
		}

		res, err := svc.UpdateEnvInlineRecipients(app.EnvInlineUpdateRecipientsRequest{
			InputPath:  c.Path,
			OutputPath: c.Path,
			PrivateKey: oldIdentity.PrivateKey,
			Recipients: []string{newIdentity.PublicKey},
		})
		if err != nil {
			return fmt.Errorf("failed to update inline secrets in %s: %w", c.Path, err)
		}
		if len(res.Updated) > 0 {
			rotatedCount++
			fmt.Fprintf(opts.stdout, "Rotated inline keys in %s: %s\n", c.Path, strings.Join(res.Updated, ", "))
		}
	}

	if rotatedCount == 0 {
		fmt.Fprintln(opts.stdout, "No age-encrypted files or inline secrets found. Key was NOT rotated.")
		return nil
	}

	// Backup old key and write new key
	keyPath := expandHome(cfg.KeyFile)
	bakPath := keyPath + ".bak"
	if err := os.Rename(keyPath, bakPath); err != nil {
		return fmt.Errorf("failed to backup old key to %s: %w", bakPath, err)
	}

	keyData := strings.Join([]string{
		"# created: " + time.Now().UTC().Format(time.RFC3339),
		"# public key: " + newIdentity.PublicKey,
		newIdentity.PrivateKey,
		"",
	}, "\n")
	if err := os.WriteFile(keyPath, []byte(keyData), 0o600); err != nil {
		return fmt.Errorf("failed to write new key to %s: %w", keyPath, err)
	}

	// Update config
	cfg.Age.Recipients = []string{newIdentity.PublicKey} // replace recipients
	cfgPath := filepath.Join(opts.cwd, primaryConfig)
	if _, err := os.Stat(cfgPath); err != nil {
		if _, errLegacy := os.Stat(filepath.Join(opts.cwd, legacyConfig)); errLegacy == nil {
			cfgPath = filepath.Join(opts.cwd, legacyConfig) // fallback
		}
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	fmt.Fprintln(opts.stdout, "✅ Key rotation complete!")
	fmt.Fprintf(opts.stdout, "  Old key backed up to: %s\n", bakPath)
	fmt.Fprintf(opts.stdout, "  New public key: %s\n", newIdentity.PublicKey)
	return nil
}
