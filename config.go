package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all connector settings, loaded from YAML with optional env-var overrides.
type Config struct {
	// CertForge connection
	CertForgeURL string        `yaml:"certforge_url"`  // e.g. https://app.certgovernance.app
	APIKey       string        `yaml:"api_key"`        // org-scoped API key from CertForge Settings
	ConnectorID  string        `yaml:"connector_id"`   // ID of the akv-keystore ca_connectors record

	// Azure Key Vault
	VaultURL string `yaml:"vault_url"` // e.g. https://myvault.vault.azure.net

	// Behaviour
	PollInterval time.Duration `yaml:"poll_interval"` // how often to check for pending jobs; default 5s
	LogLevel     string        `yaml:"log_level"`     // "info" (default) | "debug"
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Expand $ENV_VAR references in the YAML before parsing.
	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Environment variable overrides (useful for containers / Kubernetes secrets).
	if v := os.Getenv("CERTFORGE_URL"); v != "" {
		cfg.CertForgeURL = v
	}
	if v := os.Getenv("CERTFORGE_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("CONNECTOR_ID"); v != "" {
		cfg.ConnectorID = v
	}
	if v := os.Getenv("AKV_VAULT_URL"); v != "" {
		cfg.VaultURL = v
	}

	// Defaults
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Validation
	if cfg.CertForgeURL == "" {
		return nil, fmt.Errorf("certforge_url is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if cfg.ConnectorID == "" {
		return nil, fmt.Errorf("connector_id is required")
	}
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("vault_url is required")
	}

	return &cfg, nil
}
