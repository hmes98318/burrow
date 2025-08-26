package detector

import (
	"fmt"
	"log"
	"os"

	"malicious-detector/internal/shared"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Settings shared.DetectorSettings `yaml:",inline"`
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

	// Process placeholders in log regex patterns
	if err := config.ProcessPlaceholders(); err != nil {
		return nil, fmt.Errorf("failed to process placeholders: %v", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// Processes placeholders in all log regex patterns
func (c *Config) ProcessPlaceholders() error {
	// Validate placeholders first
	if err := shared.ValidatePlaceholders(c.Settings.Logs, c.Settings.Placeholders); err != nil {
		log.Printf("Warning: Placeholder validation failed: %v", err)
		return err
	}

	// Process each log configuration
	for i := range c.Settings.Logs {
		originalRegex := c.Settings.Logs[i].Regex
		processedRegex := shared.ProcessPlaceholders(originalRegex, c.Settings.Placeholders)
		c.Settings.Logs[i].Regex = processedRegex
	}

	return nil
}

func (c *Config) Validate() error {
	if c.Settings.PanelURL == "" {
		return fmt.Errorf("panel_url is required")
	}

	if c.Settings.Token == "" {
		return fmt.Errorf("token is required")
	}

	if c.Settings.Name == "" {
		return fmt.Errorf("name is required")
	}

	if len(c.Settings.Logs) == 0 {
		return fmt.Errorf("at least one log configuration is required")
	}

	// Validate each log configuration
	for i, logConfig := range c.Settings.Logs {
		if logConfig.Path == "" {
			return fmt.Errorf("log[%d]: path is required", i)
		}

		if logConfig.Regex == "" {
			return fmt.Errorf("log[%d]: regex is required", i)
		}

		if logConfig.MaxRetry <= 0 {
			return fmt.Errorf("log[%d]: max_retry must be greater than 0", i)
		}

		if logConfig.TimeWindow <= 0 {
			return fmt.Errorf("log[%d]: time_window must be greater than 0", i)
		}

		// Check if log file exists
		if _, err := os.Stat(logConfig.Path); os.IsNotExist(err) {
			return fmt.Errorf("log[%d]: log file does not exist: %s", i, logConfig.Path)
		}
	}

	return nil
}

// Outputs all successfully registered log detection configurations
func (c *Config) LogRegisteredConfigs() {
	log.Println("=== Registered Log Detection Configurations ===")
	log.Printf("Total configurations loaded: %d", len(c.Settings.Logs))

	if len(c.Settings.Placeholders) > 0 {
		log.Println("Active placeholders:")
		for key, value := range c.Settings.Placeholders {
			// Truncate long regex patterns for readability
			displayValue := value
			if len(displayValue) > 60 {
				displayValue = displayValue[:57] + "..."
			}
			log.Printf("  {{ %s }}: %s", key, displayValue)
		}
		log.Println()
	}

	for i, logConfig := range c.Settings.Logs {
		log.Printf("Configuration %d:", i+1)
		log.Printf("  Description: %s", logConfig.Description)
		log.Printf("  Log file: %s", logConfig.Path)
		log.Printf("  Scan interval: %d ms", logConfig.ScanInterval)
		log.Printf("  Max retry attempts: %d", logConfig.MaxRetry)
		log.Printf("  Time window: %d seconds", logConfig.TimeWindow)

		// Show complete processed regex pattern
		log.Printf("  Regex pattern: %s", logConfig.Regex)
		log.Println()
	}
	log.Println("=== End Configuration Summary ===")
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
		Settings: shared.DetectorSettings{
			PanelURL:          "http://your-panel-server:8080",
			Token:             "your-detector-token-here",
			Name:              "detector-1",
			IncludePrivateIPs: false, // Default to not include private IPs
			HeartbeatInterval: 10,    // Default heartbeat interval 10 seconds
			Placeholders: map[string]string{
				"ip_regex":          `((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})`,
				"ipv4_regex":        `((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))`,
				"ipv6_regex":        `((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})`,
				"http_method_regex": `(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)`,
			},
			Logs: []shared.LogConfig{
				{
					Path:         "/var/log/auth.log",
					Regex:        `Failed password for .+ from {{ ip_regex }}`,
					MaxRetry:     3,
					TimeWindow:   10,
					ScanInterval: 1000, // 1 second
					Description:  "SSH brute force detection",
				},
				{
					Path:         "/var/log/nginx/access.log",
					Regex:        `{{ ip_regex }} .+ "{{ http_method_regex }} \/\.?(?:env|git|admin|wp-admin|phpmyadmin)`,
					MaxRetry:     3,
					TimeWindow:   5,
					ScanInterval: 5000, // 5 seconds (more frequent for web logs)
					Description:  "Web vulnerability scanning detection",
				},
			},
		},
	}

	return config.Save(configPath)
}
