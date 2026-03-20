package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookScript = `#!/bin/sh
# DPX Pre-Commit Hook (Auto-generated)
# Prevents committing plaintext secrets.

if command -v dpx >/dev/null 2>&1; then
  # Only check files that are added/modified in the git index
  for file in .env .env.local .env.development .env.production .env.test; do
    if git diff --cached --name-only | grep -q "^$file$"; then
      dpx policy check "$file" > /dev/null 2>&1
      if [ $? -ne 0 ]; then
        echo "❌ DPX PRE-COMMIT BLOCK ❌"
        echo "Plaintext secrets detected in $file!"
        echo "Please run 'dpx env encrypt $file' before committing."
        exit 1
      fi
    fi
  done
fi
exit 0
`

const hookMarker = "# DPX Pre-Commit Hook (Auto-generated)"

func runHook(args []string, opts runOptions) error {
	if len(args) == 0 {
		return fmt.Errorf("hook expects a subcommand: install or uninstall")
	}
	sub := args[0]
	switch sub {
	case "install":
		return installHook(opts)
	case "uninstall":
		return uninstallHook(opts)
	default:
		return fmt.Errorf("unknown hook subcommand %q (expected install/uninstall)", sub)
	}
}

func getGitHooksDir(cwd string) (string, error) {
	gitDir := filepath.Join(cwd, ".git")
	info, err := os.Stat(gitDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("not a git repository (missing .git directory)")
		}
		return "", err
	}
	if !info.IsDir() {
		// It might be a git worktree referencing a file, but we support normal repos for simplicity.
	}
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create hooks directory: %w", err)
	}
	return hooksDir, nil
}

func installHook(opts runOptions) error {
	hooksDir, err := getGitHooksDir(opts.cwd)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")

	var currentContent []byte
	if _, err := os.Stat(hookPath); err == nil {
		currentContent, err = os.ReadFile(hookPath)
		if err != nil {
			return fmt.Errorf("failed to read existing hook: %w", err)
		}
		if strings.Contains(string(currentContent), hookMarker) {
			fmt.Fprintln(opts.stdout, "✅ DPX pre-commit hook is already installed.")
			return nil
		}
	}

	newContent := string(currentContent)
	if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	if len(newContent) == 0 || !strings.HasPrefix(strings.TrimSpace(newContent), "#!") {
		newContent = hookScript + newContent
	} else {
		newContent += "\n" + hookScript
	}

	if err := os.WriteFile(hookPath, []byte(newContent), 0o755); err != nil {
		return fmt.Errorf("failed to write pre-commit hook: %w", err)
	}
	if err := os.Chmod(hookPath, 0o755); err != nil {
		return fmt.Errorf("failed to make pre-commit hook executable: %w", err)
	}

	fmt.Fprintln(opts.stdout, "✅ DPX pre-commit hook installed successfully.")
	return nil
}

func uninstallHook(opts runOptions) error {
	hooksDir, err := getGitHooksDir(opts.cwd)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")

	if _, err := os.Stat(hookPath); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(opts.stdout, "ℹ️ No pre-commit hook found to uninstall.")
		return nil
	}

	currentContent, err := os.ReadFile(hookPath)
	if err != nil {
		return fmt.Errorf("failed to read hook file: %w", err)
	}

	contentStr := string(currentContent)
	if !strings.Contains(contentStr, hookMarker) {
		fmt.Fprintln(opts.stdout, "ℹ️ DPX pre-commit hook is not installed.")
		return nil
	}

	// Just remove the script if it matches exactly
	if strings.TrimSpace(contentStr) == strings.TrimSpace(hookScript) {
		if err := os.Remove(hookPath); err != nil {
			return fmt.Errorf("failed to remove pre-commit hook: %w", err)
		}
		fmt.Fprintln(opts.stdout, "✅ DPX pre-commit hook removed.")
		return nil
	}

	// Replace the injected DPX hook block
	parts := strings.Split(contentStr, "\n"+hookScript)
	if len(parts) == 1 {
		// Try without newline prefix
		parts = strings.Split(contentStr, hookScript)
	}
	newContent := strings.Join(parts, "")

	if err := os.WriteFile(hookPath, []byte(newContent), 0o755); err != nil {
		return fmt.Errorf("failed to rewrite hook: %w", err)
	}

	fmt.Fprintln(opts.stdout, "✅ DPX pre-commit hook removed from existing script.")
	return nil
}
