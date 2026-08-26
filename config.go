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
	CertForgeURL string `yaml:"certforge_url"` // e.g. https://app.certgov.app
	APIKey       string `yaml:"api_key"`       // org-scoped API key from CertForge Settings (not required when using mTLS)
	ConnectorID  string `yaml:"connector_id"`  // ID of the akv-keystore ca_connectors record

	// mTLS credentials (written by "certforge-akvconnector enroll").
	// When set, the connector connects directly to the CertForge mTLS port,
	// bypassing Cloudflare. api_key is not required when mTLS is configured.
	MTLSHost string `yaml:"mtls_host"` // direct-DNS hostname, e.g. usagent.certgov.app
	MTLSPort int    `yaml:"mtls_port"` // mTLS port, e.g. 8443
	MTLSCert string `yaml:"mtls_cert"` // path to PEM client certificate file
	MTLSKey  string `yaml:"mtls_key"`  // path to PEM client private key file
	MTLSCA   string `yaml:"mtls_ca"`   // path to pinned server cert PEM file

	// Azure Key Vault
	VaultURL string `yaml:"vault_url"` // e.g. https://myvault.vault.azure.net

	// Behaviour
	PollInterval  time.Duration `yaml:"poll_interval"`   // how often to check for pending jobs; default 5s
	LogLevel      string        `yaml:"log_level"`       // "info" (default) | "debug"
	PurgeOnDelete bool          `yaml:"purge_on_delete"` // permanently purge AKV certs on delete_key (bypasses soft-delete retention); requires Certificate Purge permission
}

// MTLSConfigured returns true when enough mTLS fields are set to connect via mTLS.
func (c *Config) MTLSConfigured() bool {
	return c.MTLSHost != "" && c.MTLSCert != "" && c.MTLSKey != "" && c.MTLSCA != ""
}

func loadConfig(path string) (*Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		// No config file — container deployments use environment variables only.
	} else {
		// Expand $ENV_VAR references in the YAML before parsing.
		data = []byte(os.ExpandEnv(string(data)))
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
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
	if cfg.APIKey == "" && !cfg.MTLSConfigured() {
		return nil, fmt.Errorf("api_key is required (or configure mtls_host/mtls_cert/mtls_key/mtls_ca for mTLS auth)")
	}
	if cfg.ConnectorID == "" {
		return nil, fmt.Errorf("connector_id is required")
	}
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("vault_url is required")
	}

	return &cfg, nil
}
