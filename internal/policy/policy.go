package policy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Finding struct {
	Line   int
	Key    string
	Reason string
}

type Report struct {
	Format     string
	Findings   []Finding
	SkipReason string
}

var (
	sensitiveKeyTokens = []string{
		"SECRET",
		"PASSWORD",
		"TOKEN",
		"API_KEY",
		"ACCESS_KEY",
		"PRIVATE_KEY",
		"DATABASE_URL",
		"JWT",
	}
	yamlKeyValuePattern = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*:\s*(.+?)\s*$`)
)

func Check(path string, data []byte) Report {
	if isDPXEnvelope(data) {
		return Report{Format: "dpx", SkipReason: "already encrypted dpx envelope"}
	}
	if isLikelyBinary(data) {
		return Report{Format: "binary", SkipReason: "binary file scan skipped"}
	}

	format := detectFormat(path, data)
	switch format {
	case "env", "ini":
		return Report{Format: format, Findings: checkLineAssignments(data, '=')}
	case "yaml":
		return Report{Format: format, Findings: checkYAMLLike(data)}
	case "json":
		return Report{Format: format, Findings: checkJSON(data)}
	default:
		return Report{Format: format, Findings: checkLineAssignments(data, '=')}
	}
}

func detectFormat(path string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".env":
		return "env"
	case ".ini":
		return "ini"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	}

	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	if strings.Contains(trimmed, ":") {
		return "yaml"
	}
	if strings.Contains(trimmed, "=") {
		return "env"
	}
	return "text"
}

func checkLineAssignments(data []byte, separator byte) []Finding {
	lines := strings.Split(string(data), "\n")
	findings := make([]Finding, 0, 4)
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		sepIndex := strings.IndexByte(line, separator)
		if sepIndex <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:sepIndex])
		key = strings.TrimPrefix(key, "export ")
		value := strings.TrimSpace(line[sepIndex+1:])
		value = trimWrappedQuotes(value)
		if shouldFlagPlaintext(key, value) {
			findings = append(findings, Finding{
				Line:   idx + 1,
				Key:    key,
				Reason: "sensitive key appears plaintext",
			})
		}
	}
	return findings
}

func checkYAMLLike(data []byte) []Finding {
	lines := strings.Split(string(data), "\n")
	findings := make([]Finding, 0, 4)
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "- ") {
			continue
		}
		match := yamlKeyValuePattern.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		key := strings.TrimSpace(match[1])
		value := trimWrappedQuotes(strings.TrimSpace(match[2]))
		if shouldFlagPlaintext(key, value) {
			findings = append(findings, Finding{
				Line:   idx + 1,
				Key:    key,
				Reason: "sensitive key appears plaintext",
			})
		}
	}
	return findings
}

func checkJSON(data []byte) []Finding {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil
	}
	findings := make([]Finding, 0, 4)
	walkJSON("", value, &findings)
	return findings
}

func walkJSON(path string, value any, findings *[]Finding) {
	switch typed := value.(type) {
	case map[string]any:
		for key, next := range typed {
			nextPath := key
			if path != "" {
				nextPath = path + "." + key
			}
			if text, ok := next.(string); ok && shouldFlagPlaintext(key, trimWrappedQuotes(strings.TrimSpace(text))) {
				*findings = append(*findings, Finding{
					Line:   0,
					Key:    key,
					Reason: "sensitive key appears plaintext at " + nextPath,
				})
			}
			walkJSON(nextPath, next, findings)
		}
	case []any:
		for _, next := range typed {
			walkJSON(path, next, findings)
		}
	}
}

func shouldFlagPlaintext(key, value string) bool {
	if key == "" || value == "" {
		return false
	}
	if !isSensitiveKey(key) {
		return false
	}
	if isEncryptedValue(value) {
		return false
	}
	return true
}

func isSensitiveKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, token := range sensitiveKeyTokens {
		if strings.Contains(upper, token) {
			return true
		}
	}
	return false
}

func isEncryptedValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(trimmed, "ENC["):
		return true
	case strings.HasPrefix(strings.ToLower(trimmed), "encrypted:"):
		return true
	case strings.HasPrefix(trimmed, "AGE-ENCRYPTED-"):
		return true
	default:
		return false
	}
}

func isDPXEnvelope(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return bytes.HasPrefix(trimmed, []byte("DPX-File-Version:")) || bytes.HasPrefix(trimmed, []byte("DOPX-File-Version:"))
}

func isLikelyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0x00) >= 0 {
		return true
	}
	if !utf8.Valid(data) {
		return true
	}
	nonPrintable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if b < 0x20 || b > 0x7E {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(data)) > 0.30
}

func trimWrappedQuotes(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}
