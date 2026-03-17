package discovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Candidate struct {
	Path  string
	Score int
}

var defaultPatterns = []string{".env", ".env.*", "*.env", ".secret*", ".credentials*"}

func FindCandidates(root string) ([]Candidate, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			if errorsIs(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if info.Size() == 0 {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".dpx") {
			continue
		}
		if !matchesPattern(name) {
			continue
		}
		candidates = append(candidates, Candidate{
			Path:  filepath.Join(root, name),
			Score: score(name),
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score < candidates[j].Score
		}
		return candidates[i].Path < candidates[j].Path
	})
	return candidates, nil
}

func matchesPattern(name string) bool {
	for _, pattern := range defaultPatterns {
		if ok, _ := filepath.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

func score(name string) int {
	switch {
	case name == ".env":
		return 0
	case strings.HasPrefix(name, ".env."):
		return 1
	case strings.HasSuffix(name, ".env"):
		return 2
	case strings.HasPrefix(name, ".secret"):
		return 3
	case strings.HasPrefix(name, ".credentials"):
		return 4
	default:
		return 10
	}
}

func errorsIs(err, target error) bool {
	return errors.Is(err, target)
}
