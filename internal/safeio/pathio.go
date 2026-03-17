package safeio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ReadFile(path string) ([]byte, error) {
	root, name, err := openRootForPath(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	return root.ReadFile(name)
}

func Stat(path string) (os.FileInfo, error) {
	root, name, err := openRootForPath(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	return root.Stat(name)
}

func WriteFile(path string, data []byte, mode os.FileMode) error {
	root, name, err := openRootForPath(path)
	if err != nil {
		return err
	}
	defer root.Close()

	if err := ensureWritableNonSymlink(root, name, path); err != nil {
		return err
	}
	return root.WriteFile(name, data, mode)
}

func ensureWritableNonSymlink(root *os.Root, name, originalPath string) error {
	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through symlink: %s", originalPath)
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to write to directory path: %s", originalPath)
	}
	return nil
}

func openRootForPath(path string) (*os.Root, string, error) {
	dir, name, err := splitPath(path)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}
	return root, name, nil
}

func splitPath(path string) (string, string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", "", fmt.Errorf("path is required")
	}

	abs, err := filepath.Abs(filepath.Clean(trimmed))
	if err != nil {
		return "", "", err
	}

	dir := filepath.Dir(abs)
	name := filepath.Base(abs)
	if name == string(filepath.Separator) || name == "." {
		return "", "", fmt.Errorf("path %q is not a file path", path)
	}
	return dir, name, nil
}
