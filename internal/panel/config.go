package panel

import (
	"fmt"
	"os"

	"malicious-detector/internal/shared"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Settings shared.PanelSettings `yaml:",inline"`
}

func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Apply defaults
	config.applyDefaults()

	return &config, nil
}

func (c *Config) applyDefaults() {
	if c.Settings.Port == 0 {
		c.Settings.Port = 8080
	}
	if c.Settings.HeartbeatTimeout == 0 {
		c.Settings.HeartbeatTimeout = 60 // 60 seconds default
	}
	if c.Settings.DatabasePath == "" {
		c.Settings.DatabasePath = "panel.db"
	}
}

func (c *Config) Save(configPath string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

func CreateSampleConfig(configPath string) error {
	config := &Config{
		Settings: shared.PanelSettings{
			Port:             8080,
			DatabasePath:     "panel.db",
			HeartbeatTimeout: 60,    // Heartbeat timeout in seconds, default 60s
			BlockCIDR24:      false, // Default to not aggregating IPs into /24 CIDR blocks
		},
	}

	return config.Save(configPath)
}
