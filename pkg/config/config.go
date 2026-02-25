package config

import (
	"os"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Disable          []string          `yaml:"disable"`
	SeverityOverride map[string]string `yaml:"severity-override"`
	IgnorePaths      []string          `yaml:"ignore-paths"`
}

// Load reads the configuration from the specified YAML file and returns a Config struct.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
