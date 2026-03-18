package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultRepo       = "dwirx/dpx"
	defaultBinaryName = "dpx"
)

type UpdateOptions struct {
	Version     string
	BaseURL     string
	CurrentPath string
	BackupPath  string
	GOOS        string
	GOARCH      string
	HTTPClient  *http.Client
	Progress    func(ProgressEvent)
}

type RollbackOptions struct {
	CurrentPath string
	BackupPath  string
	GOOS        string
}

type Result struct {
	CurrentPath string
	BackupPath  string
	Version     string
	Scheduled   bool
}

type ProgressEvent struct {
	Stage      string
	Message    string
	Downloaded int64
	Total      int64
	Done       bool
}

func Update(opts UpdateOptions) (Result, error) {
	goos := strings.TrimSpace(opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.TrimSpace(opts.GOARCH)
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	currentPath, err := resolveCurrentPath(opts.CurrentPath)
	if err != nil {
		return Result{}, err
	}
	backupPath := resolveBackupPath(currentPath, opts.BackupPath, goos)
	version := normalizeVersion(opts.Version)
	progress := opts.Progress

	assetName, archiveKind, err := assetInfo(goos, goarch, defaultBinaryName)
	if err != nil {
		return Result{}, err
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "resolve",
		Message: fmt.Sprintf("Resolving release asset (%s)", assetName),
		Done:    true,
	})
	baseURL := resolveBaseURL(opts.BaseURL, version)
	assetURL := strings.TrimRight(baseURL, "/") + "/" + assetName
	checksumURL := strings.TrimRight(baseURL, "/") + "/checksums.txt"

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}

	assetData, err := download(httpClient, assetURL, func(downloaded, total int64, done bool) {
		emitProgress(progress, ProgressEvent{
			Stage:      "download",
			Message:    fmt.Sprintf("Downloading %s", assetName),
			Downloaded: downloaded,
			Total:      total,
			Done:       done,
		})
	})
	if err != nil {
		return Result{}, err
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "verify",
		Message: "Verifying checksums",
		Done:    false,
	})
	if err := verifyChecksumIfAvailable(httpClient, checksumURL, assetName, assetData); err != nil {
		return Result{}, err
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "verify",
		Message: "Verifying checksums",
		Done:    true,
	})

	binaryName := defaultBinaryName
	if goos == "windows" {
		binaryName = defaultBinaryName + ".exe"
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "extract",
		Message: fmt.Sprintf("Extracting %s", binaryName),
		Done:    false,
	})
	binaryData, err := extractBinary(assetData, archiveKind, binaryName)
	if err != nil {
		return Result{}, err
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "extract",
		Message: fmt.Sprintf("Extracting %s", binaryName),
		Done:    true,
	})

	if goos == "windows" {
		emitProgress(progress, ProgressEvent{
			Stage:   "schedule",
			Message: "Scheduling Windows binary replacement",
			Done:    false,
		})
		if err := scheduleWindowsReplace(currentPath, backupPath, binaryData); err != nil {
			return Result{}, err
		}
		emitProgress(progress, ProgressEvent{
			Stage:   "schedule",
			Message: "Scheduling Windows binary replacement",
			Done:    true,
		})
		emitProgress(progress, ProgressEvent{
			Stage:   "done",
			Message: "Update scheduled",
			Done:    true,
		})
		return Result{
			CurrentPath: currentPath,
			BackupPath:  backupPath,
			Version:     versionOrLatest(version),
			Scheduled:   true,
		}, nil
	}

	emitProgress(progress, ProgressEvent{
		Stage:   "install",
		Message: "Replacing current binary",
		Done:    false,
	})
	if err := replaceBinaryAtomic(currentPath, backupPath, binaryData); err != nil {
		return Result{}, err
	}
	emitProgress(progress, ProgressEvent{
		Stage:   "install",
		Message: "Replacing current binary",
		Done:    true,
	})
	emitProgress(progress, ProgressEvent{
		Stage:   "done",
		Message: "Update completed",
		Done:    true,
	})
	return Result{
		CurrentPath: currentPath,
		BackupPath:  backupPath,
		Version:     versionOrLatest(version),
	}, nil
}

func Rollback(opts RollbackOptions) (Result, error) {
	goos := strings.TrimSpace(opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	currentPath, err := resolveCurrentPath(opts.CurrentPath)
	if err != nil {
		return Result{}, err
	}
	backupPath := resolveBackupPath(currentPath, opts.BackupPath, goos)
	if _, err := os.Stat(backupPath); err != nil {
		if os.IsNotExist(err) {
			return Result{}, fmt.Errorf("rollback backup not found: %s", backupPath)
		}
		return Result{}, err
	}

	if goos == "windows" {
		if err := scheduleWindowsRollback(currentPath, backupPath); err != nil {
			return Result{}, err
		}
		return Result{
			CurrentPath: currentPath,
			BackupPath:  backupPath,
			Scheduled:   true,
		}, nil
	}

	failedPath := currentPath + ".failed"
	_ = os.Remove(failedPath)
	if err := os.Rename(currentPath, failedPath); err != nil {
		return Result{}, err
	}
	if err := os.Rename(backupPath, currentPath); err != nil {
		_ = os.Rename(failedPath, currentPath)
		return Result{}, err
	}
	_ = os.Remove(failedPath)
	return Result{
		CurrentPath: currentPath,
		BackupPath:  backupPath,
	}, nil
}

func resolveCurrentPath(path string) (string, error) {
	if strings.TrimSpace(path) != "" {
		return path, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		return resolved, nil
	}
	return exe, nil
}

func resolveBackupPath(currentPath, backupPath, goos string) string {
	if strings.TrimSpace(backupPath) != "" {
		return backupPath
	}
	if goos == "windows" {
		if strings.HasSuffix(strings.ToLower(currentPath), ".exe") {
			return strings.TrimSuffix(currentPath, ".exe") + ".rollback.exe"
		}
		return currentPath + ".rollback.exe"
	}
	return currentPath + ".rollback"
}

func assetInfo(goos, goarch, binaryName string) (asset string, archiveKind string, err error) {
	if goarch != "amd64" && goarch != "arm64" {
		return "", "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
	switch goos {
	case "linux", "darwin":
		return fmt.Sprintf("%s_%s_%s.tar.gz", binaryName, goos, goarch), "tar.gz", nil
	case "windows":
		return fmt.Sprintf("%s_%s_%s.zip", binaryName, goos, goarch), "zip", nil
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", goos)
	}
}

func resolveBaseURL(rawBaseURL, version string) string {
	baseURL := strings.TrimSpace(rawBaseURL)
	if baseURL != "" {
		return strings.TrimRight(baseURL, "/")
	}
	if version == "" {
		return "https://github.com/" + defaultRepo + "/releases/latest/download"
	}
	return "https://github.com/" + defaultRepo + "/releases/download/" + version
}

func normalizeVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

func versionOrLatest(version string) string {
	if version == "" {
		return "latest"
	}
	return version
}

func download(client *http.Client, rawURL string, onProgress func(downloaded, total int64, done bool)) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dpx-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s failed: HTTP %d", rawURL, resp.StatusCode)
	}
	total := resp.ContentLength
	if onProgress != nil {
		onProgress(0, total, false)
	}
	buffer := bytes.NewBuffer(nil)
	chunk := make([]byte, 32*1024)
	var downloaded int64
	for {
		n, readErr := resp.Body.Read(chunk)
		if n > 0 {
			if _, err := buffer.Write(chunk[:n]); err != nil {
				return nil, err
			}
			downloaded += int64(n)
			if onProgress != nil {
				onProgress(downloaded, total, false)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if onProgress != nil {
		onProgress(downloaded, total, true)
	}
	return buffer.Bytes(), nil
}

func verifyChecksumIfAvailable(client *http.Client, checksumURL, assetName string, assetData []byte) error {
	checksumData, err := download(client, checksumURL, nil)
	if err != nil {
		return nil
	}
	expected := ""
	for _, line := range strings.Split(string(checksumData), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "./")
		if name == assetName {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return nil
	}
	gotRaw := sha256.Sum256(assetData)
	got := hex.EncodeToString(gotRaw[:])
	if !strings.EqualFold(expected, got) {
		return fmt.Errorf("checksum mismatch for %s", assetName)
	}
	return nil
}

func extractBinary(archiveData []byte, archiveKind, binaryName string) ([]byte, error) {
	switch archiveKind {
	case "tar.gz":
		gzReader, err := gzip.NewReader(bytes.NewReader(archiveData))
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		tarReader := tar.NewReader(gzReader)
		for {
			hdr, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			name := filepath.Base(hdr.Name)
			if name != binaryName {
				continue
			}
			return io.ReadAll(tarReader)
		}
	case "zip":
		zr, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			name := filepath.Base(f.Name)
			if name != binaryName {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %s not found in archive", binaryName)
}

func replaceBinaryAtomic(currentPath, backupPath string, newBinary []byte) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return err
	}
	mode := info.Mode() & os.ModePerm
	if mode == 0 {
		mode = 0o755
	}

	dir := filepath.Dir(currentPath)
	tmpFile, err := os.CreateTemp(dir, ".dpx-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(newBinary); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(mode); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	_ = os.Remove(backupPath)
	if err := os.Rename(currentPath, backupPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func scheduleWindowsReplace(currentPath, backupPath string, newBinary []byte) error {
	dir := filepath.Dir(currentPath)
	newPath := filepath.Join(dir, ".dpx-update.new.exe")
	if err := os.WriteFile(newPath, newBinary, 0o755); err != nil {
		return err
	}
	scriptPath := filepath.Join(dir, ".dpx-update.cmd")
	script := strings.Join([]string{
		"@echo off",
		"setlocal",
		`set "TARGET=` + windowsEscape(currentPath) + `"`,
		`set "BACKUP=` + windowsEscape(backupPath) + `"`,
		`set "NEWFILE=` + windowsEscape(newPath) + `"`,
		"set RETRIES=0",
		":retry",
		"set /A RETRIES+=1",
		`move /Y "%TARGET%" "%BACKUP%" >nul 2>nul`,
		"if errorlevel 1 (",
		"  if %RETRIES% GEQ 60 goto fail",
		"  timeout /t 1 /nobreak >nul",
		"  goto retry",
		")",
		`move /Y "%NEWFILE%" "%TARGET%" >nul 2>nul`,
		"if errorlevel 1 goto fail",
		"del /f /q %~f0 >nul 2>nul",
		"exit /b 0",
		":fail",
		"exit /b 1",
	}, "\r\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("cmd", "/C", "start", "", "/B", scriptPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func scheduleWindowsRollback(currentPath, backupPath string) error {
	dir := filepath.Dir(currentPath)
	failedPath := currentPath + ".failed"
	scriptPath := filepath.Join(dir, ".dpx-rollback.cmd")
	script := strings.Join([]string{
		"@echo off",
		"setlocal",
		`set "TARGET=` + windowsEscape(currentPath) + `"`,
		`set "BACKUP=` + windowsEscape(backupPath) + `"`,
		`set "FAILED=` + windowsEscape(failedPath) + `"`,
		"set RETRIES=0",
		":retry",
		"set /A RETRIES+=1",
		`move /Y "%TARGET%" "%FAILED%" >nul 2>nul`,
		"if errorlevel 1 (",
		"  if %RETRIES% GEQ 60 goto fail",
		"  timeout /t 1 /nobreak >nul",
		"  goto retry",
		")",
		`move /Y "%BACKUP%" "%TARGET%" >nul 2>nul`,
		"if errorlevel 1 goto fail",
		`del /f /q "%FAILED%" >nul 2>nul`,
		"del /f /q %~f0 >nul 2>nul",
		"exit /b 0",
		":fail",
		"exit /b 1",
	}, "\r\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("cmd", "/C", "start", "", "/B", scriptPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func emitProgress(handler func(ProgressEvent), event ProgressEvent) {
	if handler == nil {
		return
	}
	handler(event)
}

func windowsEscape(path string) string {
	escaped := strings.ReplaceAll(path, `"`, `""`)
	return strings.ReplaceAll(escaped, "/", `\`)
}
