package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dwirx/dpx/internal/app"
	"github.com/dwirx/dpx/internal/config"
)

const (
	primaryConfigName = ".dpx.yaml"
	legacyConfigName  = ".dopx.yaml"
)

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

type keyImportSyncResult struct {
	Path           string
	RecipientAdded bool
	LegacyMigrated bool
}

func importIdentityAndSyncConfig(svc app.Service, cwd string, cfg config.Config, outputPath, raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("key data is required")
	}
	rawOut := strings.TrimSpace(outputPath)
	if rawOut == "" {
		rawOut = cfg.KeyFile
	}
	expandedOut := expandHome(rawOut)
	identity, err := svc.ImportIdentity(expandedOut, raw)
	if err != nil {
		return "", err
	}

	syncResult, err := syncImportedKeyConfig(cwd, rawOut, identity.PublicKey)
	if err != nil {
		return "", err
	}

	lines := []string{
		fmt.Sprintf("Imported key -> %s", expandedOut),
		fmt.Sprintf("Public Key: %s", identity.PublicKey),
		fmt.Sprintf("Updated config: %s", syncResult.Path),
	}
	if syncResult.RecipientAdded {
		lines = append(lines, "Added public key to age.recipients")
	} else {
		lines = append(lines, "Public key already exists in age.recipients")
	}
	if syncResult.LegacyMigrated {
		lines = append(lines, "Legacy .dopx.yaml detected, settings written to .dpx.yaml")
	}
	return strings.Join(lines, "\n"), nil
}

func syncImportedKeyConfig(cwd, keyFilePath, publicKey string) (keyImportSyncResult, error) {
	source, err := resolveConfigSource(cwd)
	if err != nil {
		return keyImportSyncResult{}, err
	}

	targetPath := filepath.Join(cwd, primaryConfigName)
	cfg := config.Default()
	result := keyImportSyncResult{Path: targetPath}

	if source.Exists {
		loaded, err := config.Load(source.Path)
		if err != nil {
			return keyImportSyncResult{}, err
		}
		cfg = loaded
		if !source.Legacy {
			targetPath = source.Path
			result.Path = targetPath
		} else {
			result.LegacyMigrated = true
		}
	}

	cfg.KeyFile = keyFilePath
	if !containsString(cfg.Age.Recipients, publicKey) {
		cfg.Age.Recipients = append(cfg.Age.Recipients, publicKey)
		result.RecipientAdded = true
	}

	if err := config.Save(targetPath, cfg); err != nil {
		return keyImportSyncResult{}, err
	}
	return result, nil
}

func collectDoctorReportForTUI(svc app.Service, cwd string, cfg config.Config) (doctorReport, error) {
	source, err := resolveConfigSource(cwd)
	if err != nil {
		return doctorReport{}, err
	}
	report := doctorReport{Config: source}

	loadedCfg := cfg
	if source.Exists {
		loaded, err := config.Load(source.Path)
		if err != nil {
			report.ConfigError = err
		} else {
			loadedCfg = loaded
		}
	}

	report.RecipientCount = len(loadedCfg.Age.Recipients)
	report.KeyPath = expandHome(loadedCfg.KeyFile)
	if _, err := os.Stat(report.KeyPath); err == nil {
		report.KeyExists = true
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return doctorReport{}, err
	} else if loadedCfg.KeyFile == config.DefaultKeyFile {
		legacyPath := expandHome(config.LegacyKeyFile)
		if _, legacyErr := os.Stat(legacyPath); legacyErr == nil {
			report.KeyPath = legacyPath
			report.KeyExists = true
			report.KeyUsesLegacy = true
		} else if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
			return doctorReport{}, legacyErr
		}
	}

	candidates, err := svc.Discover(cwd)
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

func formatDoctorReport(report doctorReport) string {
	var b strings.Builder
	b.WriteString("DPX Doctor\n\n")

	switch {
	case report.ConfigError != nil:
		fmt.Fprintf(&b, "Config: ERROR (%s)\n", report.Config.Path)
		fmt.Fprintf(&b, "Config Error: %v\n", report.ConfigError)
	case report.Config.Exists && report.Config.Legacy:
		fmt.Fprintf(&b, "Config: OK (%s, legacy)\n", report.Config.Path)
	case report.Config.Exists:
		fmt.Fprintf(&b, "Config: OK (%s)\n", report.Config.Path)
	default:
		fmt.Fprintf(&b, "Config: MISSING (%s)\n", report.Config.Path)
	}

	switch {
	case report.KeyExists && report.KeyUsesLegacy:
		fmt.Fprintf(&b, "Key File: OK (%s, legacy fallback)\n", report.KeyPath)
	case report.KeyExists:
		fmt.Fprintf(&b, "Key File: OK (%s)\n", report.KeyPath)
	default:
		fmt.Fprintf(&b, "Key File: MISSING (%s)\n", report.KeyPath)
	}

	fmt.Fprintf(&b, "Recipients: %d\n", report.RecipientCount)
	fmt.Fprintf(&b, "Suggested Files: %d\n", report.SuggestedFiles)
	fmt.Fprintf(&b, "Encrypted Files: %d\n", report.EncryptedFiles)
	return b.String()
}

func resolveConfigSource(cwd string) (configSource, error) {
	primaryPath := filepath.Join(cwd, primaryConfigName)
	if _, err := os.Stat(primaryPath); err == nil {
		return configSource{Path: primaryPath, Exists: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return configSource{}, err
	}

	legacyPath := filepath.Join(cwd, legacyConfigName)
	if _, err := os.Stat(legacyPath); err == nil {
		return configSource{Path: legacyPath, Exists: true, Legacy: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return configSource{}, err
	}

	return configSource{Path: primaryPath}, nil
}

func expandHome(path string) string {
	rest, ok := trimHomePrefix(path)
	if !ok {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	rest = strings.ReplaceAll(rest, "\\", string(os.PathSeparator))
	rest = strings.ReplaceAll(rest, "/", string(os.PathSeparator))
	return filepath.Join(home, rest)
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func trimHomePrefix(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "~/"):
		return path[2:], true
	case strings.HasPrefix(path, "~\\"):
		return path[2:], true
	default:
		return "", false
	}
}
