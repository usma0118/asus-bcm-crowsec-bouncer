package config

import (
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type BouncerConfig struct {
	APIURL             string `yaml:"api_url"`
	APIKey             string `yaml:"api_key"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

func Load(path string) (*BouncerConfig, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var cfg BouncerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func ResolveLAPIParams(cfg *BouncerConfig, log *zap.Logger) (string, string, bool) {
	// URL
	lapiURL := os.Getenv("LAPI_URL")
	if lapiURL == "" {
		lapiURL = cfg.APIURL
	}
	if lapiURL == "" {
		lapiURL = "http://crowdsec-lapi.crowdsec.svc.cluster.local:8080"
	}

	// API key
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		raw := strings.TrimSpace(cfg.APIKey)
		if raw != "" {
			if strings.HasPrefix(raw, "${") && strings.HasSuffix(raw, "}") {
				envName := strings.TrimSuffix(strings.TrimPrefix(raw, "${"), "}")
				apiKey = os.Getenv(envName)
			} else {
				apiKey = raw
			}
		}
	}
	if apiKey == "" {
		log.Fatal("API key missing (API_KEY env or api_key in YAML)")
	}

	// TLS verify
	insecure := cfg.InsecureSkipVerify
	if v := os.Getenv("INSECURE_SKIP_VERIFY"); v != "" {
		insecure = strings.EqualFold(v, "true")
	}

	return lapiURL, apiKey, insecure
}
