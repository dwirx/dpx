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

var commonFileTypeScores = map[string]int{
	".txt":      5,
	".md":       6,
	".markdown": 6,
	".js":       7,
	".mjs":      7,
	".cjs":      7,
	".ts":       8,
	".tsx":      8,
	".jsx":      8,
	".json":     9,
	".yaml":     10,
	".yml":      10,
	".toml":     10,
	".ini":      10,
	".cfg":      10,
	".conf":     10,
	".xml":      11,
	".csv":      11,
	".log":      11,
	".sh":       12,
	".ps1":      12,
	".bat":      12,
	".bin":      13,
	".exe":      13,
}

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

func FindEncryptTargets(root string) ([]Candidate, error) {
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
		candidates = append(candidates, Candidate{
			Path:  filepath.Join(root, name),
			Score: scoreEncryptTarget(name),
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

func scoreEncryptTarget(name string) int {
	if matchesPattern(name) {
		return score(name)
	}

	ext := strings.ToLower(filepath.Ext(name))
	if score, ok := commonFileTypeScores[ext]; ok {
		return score
	}

	if strings.HasPrefix(name, ".") {
		return 30
	}
	return 20
}

func errorsIs(err, target error) bool {
	return errors.Is(err, target)
}
