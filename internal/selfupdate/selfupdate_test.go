package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAssetInfo(t *testing.T) {
	t.Parallel()

	asset, kind, err := assetInfo("linux", "amd64", "dpx")
	if err != nil {
		t.Fatalf("assetInfo linux amd64: %v", err)
	}
	if asset != "dpx_linux_amd64.tar.gz" || kind != "tar.gz" {
		t.Fatalf("unexpected asset info: %q %q", asset, kind)
	}

	asset, kind, err = assetInfo("windows", "arm64", "dpx")
	if err != nil {
		t.Fatalf("assetInfo windows arm64: %v", err)
	}
	if asset != "dpx_windows_arm64.zip" || kind != "zip" {
		t.Fatalf("unexpected asset info: %q %q", asset, kind)
	}
}

func TestDownloadReportsProgress(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("x"), 96*1024+17)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	var (
		sawProgress bool
		finalBytes  int64
		finalTotal  int64
		doneEvents  int
	)
	data, err := download(http.DefaultClient, server.URL, func(downloaded, total int64, done bool) {
		sawProgress = true
		finalBytes = downloaded
		finalTotal = total
		if done {
			doneEvents++
		}
	})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("downloaded payload mismatch")
	}
	if !sawProgress {
		t.Fatal("expected progress callback to be invoked")
	}
	if finalBytes != int64(len(payload)) {
		t.Fatalf("expected final downloaded %d, got %d", len(payload), finalBytes)
	}
	if finalTotal != int64(len(payload)) {
		t.Fatalf("expected total %d, got %d", len(payload), finalTotal)
	}
	if doneEvents == 0 {
		t.Fatal("expected at least one done progress event")
	}
}

func TestUpdateReplacesBinaryAndCreatesBackup(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("non-windows atomic replace test")
	}

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos != "linux" && goos != "darwin" {
		t.Skip("unsupported test OS")
	}
	if goarch != "amd64" && goarch != "arm64" {
		t.Skip("unsupported test arch")
	}

	oldBinary := []byte("old-binary")
	newBinary := []byte("new-binary")
	assetName, _, err := assetInfo(goos, goarch, defaultBinaryName)
	if err != nil {
		t.Fatalf("assetInfo: %v", err)
	}
	archive := mustTarGzWithFile(t, defaultBinaryName, newBinary)
	checksums := checksumsFor(t, assetName, archive)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + assetName:
			_, _ = w.Write(archive)
		case "/checksums.txt":
			_, _ = w.Write([]byte(checksums))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	currentPath := filepath.Join(dir, "dpx")
	backupPath := filepath.Join(dir, "dpx.rollback")
	if err := os.WriteFile(currentPath, oldBinary, 0o755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	result, err := Update(UpdateOptions{
		BaseURL:     server.URL,
		CurrentPath: currentPath,
		BackupPath:  backupPath,
		GOOS:        goos,
		GOARCH:      goarch,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if result.Scheduled {
		t.Fatalf("expected non-windows update to be immediate")
	}

	currentData, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("read current binary: %v", err)
	}
	if !bytes.Equal(currentData, newBinary) {
		t.Fatalf("current binary mismatch: got %q want %q", currentData, newBinary)
	}

	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup binary: %v", err)
	}
	if !bytes.Equal(backupData, oldBinary) {
		t.Fatalf("backup binary mismatch: got %q want %q", backupData, oldBinary)
	}
}

func TestUpdateFailsOnChecksumMismatch(t *testing.T) {
	t.Parallel()

	goos := runtime.GOOS
	goarch := runtime.GOARCH
	if goos != "linux" && goos != "darwin" && goos != "windows" {
		t.Skip("unsupported test OS")
	}
	if goarch != "amd64" && goarch != "arm64" {
		t.Skip("unsupported test arch")
	}

	assetName, kind, err := assetInfo(goos, goarch, defaultBinaryName)
	if err != nil {
		t.Fatalf("assetInfo: %v", err)
	}
	var archive []byte
	fileName := defaultBinaryName
	if goos == "windows" {
		fileName = defaultBinaryName + ".exe"
		archive = mustZipWithFile(t, fileName, []byte("new-binary"))
	} else {
		archive = mustTarGzWithFile(t, fileName, []byte("new-binary"))
	}
	_ = kind

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + assetName:
			_, _ = w.Write(archive)
		case "/checksums.txt":
			_, _ = w.Write([]byte(fmt.Sprintf("%s  %s\n", strings.Repeat("0", 64), assetName)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	currentPath := filepath.Join(dir, "dpx")
	if goos == "windows" {
		currentPath += ".exe"
	}
	if err := os.WriteFile(currentPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}

	_, err = Update(UpdateOptions{
		BaseURL:     server.URL,
		CurrentPath: currentPath,
		GOOS:        goos,
		GOARCH:      goarch,
	})
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "checksum mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRollbackRestoresBackup(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("non-windows rollback test")
	}

	dir := t.TempDir()
	currentPath := filepath.Join(dir, "dpx")
	backupPath := filepath.Join(dir, "dpx.rollback")
	if err := os.WriteFile(currentPath, []byte("new-binary"), 0o755); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	result, err := Rollback(RollbackOptions{
		CurrentPath: currentPath,
		BackupPath:  backupPath,
		GOOS:        runtime.GOOS,
	})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if result.Scheduled {
		t.Fatalf("expected non-windows rollback to be immediate")
	}
	data, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatalf("read current after rollback: %v", err)
	}
	if string(data) != "old-binary" {
		t.Fatalf("rollback content mismatch: got %q", data)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected backup consumed after rollback, stat err=%v", err)
	}
}

func mustTarGzWithFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func mustZipWithFile(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writer, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func checksumsFor(t *testing.T, name string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), name)
}
