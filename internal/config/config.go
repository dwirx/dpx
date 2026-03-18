package config

import (
	"os"
	"path/filepath"

	"github.com/dwirx/dpx/internal/safeio"
	"gopkg.in/yaml.v3"
)

const (
	DefaultKeyFile = "~/.config/dpx/age-keys.txt"
	LegacyKeyFile  = "~/.config/dopx/age-keys.txt"
)

type Config struct {
	Version       int             `yaml:"version"`
	DefaultSuffix string          `yaml:"default_suffix"`
	KeyFile       string          `yaml:"key_file"`
	Age           AgeConfig       `yaml:"age"`
	Discovery     DiscoveryConfig `yaml:"discovery"`
	Policy        PolicyConfig    `yaml:"policy"`
}

type AgeConfig struct {
	Recipients []string `yaml:"recipients"`
}

type DiscoveryConfig struct {
	Include []string `yaml:"include"`
}

type PolicyConfig struct {
	CreationRules []CreationRule `yaml:"creation_rules"`
}

type CreationRule struct {
	Path        string   `yaml:"path"`
	Mode        string   `yaml:"mode"`
	EncryptKeys []string `yaml:"encrypt_keys"`
}

func Default() Config {
	return Config{
		Version:       1,
		DefaultSuffix: ".dpx",
		KeyFile:       DefaultKeyFile,
		Discovery: DiscoveryConfig{
			Include: []string{".env", ".env.*", "*.env", ".secret*", ".credentials*"},
		},
	}
}

func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := safeio.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Discovery.Include == nil {
		cfg.Discovery.Include = Default().Discovery.Include
	}
	if cfg.DefaultSuffix == "" {
		cfg.DefaultSuffix = Default().DefaultSuffix
	}
	if cfg.KeyFile == "" {
		cfg.KeyFile = Default().KeyFile
	}
	if cfg.Version == 0 {
		cfg.Version = Default().Version
	}
	if cfg.Policy.CreationRules == nil {
		cfg.Policy.CreationRules = []CreationRule{}
	}
	return cfg, nil
}
