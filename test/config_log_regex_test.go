package test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"malicious-detector/internal/shared"

	"gopkg.in/yaml.v3"
)

// LogTest represents a test case for log regex
type LogTest struct {
	Description string // Test case description explaining what this test validates
	Log         string // The actual log line content to be tested against the regex
	ExpectedIP  string // The IP address that should be extracted from the log (empty if no match expected)
	ShouldMatch bool   // Whether the regex should match this log line (true = should match, false = should not match)
}

// Test logs for different services
var testLogs = map[string][]LogTest{
	"SSH brute force detection": {
		{
			Description: "Failed SSH login with valid IP",
			Log:         "Sep 07 15:35:11 server sshd[1234]: Failed password for root from 203.0.113.100 port 22 ssh2",
			ExpectedIP:  "203.0.113.100",
			ShouldMatch: true,
		},
		{
			Description: "Failed SSH login with different user",
			Log:         "Sep 07 15:35:12 server sshd[5678]: Failed password for testuser from 198.51.100.50 port 22 ssh2",
			ExpectedIP:  "198.51.100.50",
			ShouldMatch: true,
		},
		{
			Description: "Successful SSH login (should not match)",
			Log:         "Sep 07 15:35:13 server sshd[9999]: Accepted password for user from 192.168.1.100 port 22 ssh2",
			ExpectedIP:  "",
			ShouldMatch: false,
		},
		{
			Description: "Invalid IP format",
			Log:         "Sep 07 15:35:14 server sshd[1111]: Failed password for root from 999.999.999.999 port 22 ssh2",
			ExpectedIP:  "",
			ShouldMatch: false, // Invalid IP should not match the regex
		},
		{
			Description: "No IP in failed login message",
			Log:         "Sep 07 15:35:15 server sshd[2222]: Failed password for root from invalid_host port 22 ssh2",
			ExpectedIP:  "",
			ShouldMatch: false,
		},
	},
	"Nginx vulnerability scanning detection": {
		{
			Description: "GET request for .env file",
			Log:         `203.0.113.100 - - [07/Sep/2025:15:30:45 +0800] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"`,
			ExpectedIP:  "203.0.113.100",
			ShouldMatch: true,
		},
		{
			Description: "POST request to wp-admin",
			Log:         `198.51.100.52 - - [07/Sep/2025:15:30:46 +0800] "POST /wp-admin/admin-ajax.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"`,
			ExpectedIP:  "198.51.100.52",
			ShouldMatch: true,
		},
		{
			Description: "GET request for admin",
			Log:         `194.5.48.200 - - [07/Sep/2025:15:30:47 +0800] "GET /admin/index.php HTTP/1.1" 404 162 "-" "Scanner"`,
			ExpectedIP:  "194.5.48.200",
			ShouldMatch: true,
		},
		{
			Description: "GET request for .git",
			Log:         `203.0.113.99 - - [07/Sep/2025:15:30:48 +0800] "GET /.git/config HTTP/1.1" 404 162 "-" "curl/7.68.0"`,
			ExpectedIP:  "203.0.113.99",
			ShouldMatch: true,
		},
		{
			Description: "Normal GET request (should not match)",
			Log:         `192.168.1.100 - - [07/Sep/2025:15:30:49 +0800] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
			ExpectedIP:  "",
			ShouldMatch: false,
		},
	},
	"Apache vulnerability scanning detection": {
		{
			Description: "GET request for .htaccess",
			Log:         `203.0.113.200 - - [07/Sep/2025:15:35:01 +0800] "GET /.htaccess HTTP/1.1" 403 210 "-" "curl/7.68.0"`,
			ExpectedIP:  "203.0.113.200",
			ShouldMatch: true,
		},
		{
			Description: "POST request to config.php",
			Log:         `198.51.100.75 - - [07/Sep/2025:15:35:02 +0800] "POST /config.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"`,
			ExpectedIP:  "198.51.100.75",
			ShouldMatch: true,
		},
		{
			Description: "Normal request (should not match)",
			Log:         `192.168.1.100 - - [07/Sep/2025:15:35:03 +0800] "GET /page.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"`,
			ExpectedIP:  "",
			ShouldMatch: false,
		},
	},
	"FTP brute force detection": {
		{
			Description: "FTP login failure",
			Log:         `Mon Sep  7 15:40:01 2025 [pid 12345] FAIL LOGIN: Client "203.0.113.150"`,
			ExpectedIP:  "203.0.113.150",
			ShouldMatch: true,
		},
		{
			Description: "Another FTP login failure",
			Log:         `Mon Sep  7 15:40:02 2025 [pid 12346] FAIL LOGIN: Client "194.5.48.100"`,
			ExpectedIP:  "194.5.48.100",
			ShouldMatch: true,
		},
		{
			Description: "Successful FTP login (should not match)",
			Log:         `Mon Sep  7 15:40:03 2025 [pid 12347] OK LOGIN: Client "192.168.1.100"`,
			ExpectedIP:  "",
			ShouldMatch: false,
		},
	},
	"Nextcloud brute force detection": {
		{
			Description: "Nextcloud brute force attempt 1",
			Log:         `{"reqId":"BAD4exjcE0NFcbMVza7Y","level":1,"time":"2025-09-04T15:43:46+08:00","remoteAddr":"194.5.48.219","user":"--","app":"core","method":"POST","url":"/login","message":"Bruteforce attempt from \"194.5.48.219\" detected for action \"login\".","userAgent":"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)","version":"27.1.11.3","data":{"app":"core"}}`,
			ExpectedIP:  "194.5.48.219",
			ShouldMatch: true,
		},
		{
			Description: "Nextcloud brute force attempt 2",
			Log:         `{"reqId":"EYHTui1IOCjjh44KFpaJ","level":1,"time":"2025-09-04T15:43:47+08:00","remoteAddr":"194.5.48.210","user":"--","app":"core","method":"POST","url":"/login","message":"Bruteforce attempt from \"194.5.48.210\" detected for action \"login\".","userAgent":"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)","version":"27.1.11.3","data":{"app":"core"}}`,
			ExpectedIP:  "194.5.48.210",
			ShouldMatch: true,
		},
		{
			Description: "Normal Nextcloud request (should not match)",
			Log:         `{"reqId":"normalRequest123","level":0,"time":"2025-09-04T15:44:00+08:00","remoteAddr":"192.168.1.100","user":"admin","app":"core","method":"GET","url":"/dashboard","message":"Normal login successful","userAgent":"Mozilla/5.0","version":"27.1.11.3","data":{"app":"core"}}`,
			ExpectedIP:  "",
			ShouldMatch: false,
		},
	},
}

// loadDetectorConfig loads the detector sample configuration with placeholder processing
func loadDetectorConfig(t *testing.T) *shared.DetectorSettings {
	// Get the project root directory
	projectRoot := ".."
	configPath := filepath.Join(projectRoot, "configs", "detector-sample.yaml")

	// Read original config
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read detector config file: %v", err)
	}

	// Parse YAML directly to get settings with placeholder processing
	var config struct {
		Settings shared.DetectorSettings `yaml:",inline"`
	}

	if err := yaml.Unmarshal(configData, &config); err != nil {
		t.Fatalf("Failed to parse config file: %v", err)
	}

	// Process placeholders manually for testing
	if err := shared.ValidatePlaceholders(config.Settings.Logs, config.Settings.Placeholders); err != nil {
		t.Fatalf("Placeholder validation failed: %v", err)
	}

	// Process each log configuration
	for i := range config.Settings.Logs {
		originalRegex := config.Settings.Logs[i].Regex
		processedRegex := shared.ProcessPlaceholders(originalRegex, config.Settings.Placeholders)
		config.Settings.Logs[i].Regex = processedRegex
	}

	return &config.Settings
}

// TestLogRegexes tests all log regex patterns from detector-sample.yaml
func TestLogRegexes(t *testing.T) {
	config := loadDetectorConfig(t)

	// Create a map of description to log config for easy lookup
	logConfigs := make(map[string]shared.LogConfig)
	for _, logConfig := range config.Logs {
		logConfigs[logConfig.Description] = logConfig
	}

	// Test each log type
	for description, tests := range testLogs {
		t.Run(description, func(t *testing.T) {
			logConfig, exists := logConfigs[description]
			if !exists {
				t.Fatalf("Log configuration not found for: %s", description)
			}

			// Compile the regex
			regex, err := regexp.Compile(logConfig.Regex)
			if err != nil {
				t.Fatalf("Failed to compile regex for %s: %v", description, err)
			}

			// Test each log entry
			for _, test := range tests {
				t.Run(test.Description, func(t *testing.T) {
					matches := regex.FindStringSubmatch(test.Log)

					if test.ShouldMatch {
						if len(matches) < 2 {
							t.Errorf("Expected to match IP, but regex did not match\nLog: %s\nRegex: %s", test.Log, logConfig.Regex)
							return
						}

						extractedIP := matches[1]
						if extractedIP != test.ExpectedIP {
							t.Errorf("Expected IP %s, but got %s\nLog: %s\nRegex: %s", test.ExpectedIP, extractedIP, test.Log, logConfig.Regex)
						}
					} else {
						if len(matches) >= 2 {
							t.Errorf("Expected not to match, but regex matched IP %s\nLog: %s\nRegex: %s", matches[1], test.Log, logConfig.Regex)
						}
					}
				})
			}
		})
	}
}

// TestConfigurationConsistency tests that all log configs in detector-sample.yaml have corresponding tests
func TestConfigurationConsistency(t *testing.T) {
	config := loadDetectorConfig(t)

	// Check that all log configs have tests
	for _, logConfig := range config.Logs {
		if _, exists := testLogs[logConfig.Description]; !exists {
			t.Errorf("No test cases found for log configuration: %s", logConfig.Description)
		}
	}

	// Check that all tests have corresponding log configs
	logConfigDescriptions := make(map[string]bool)
	for _, logConfig := range config.Logs {
		logConfigDescriptions[logConfig.Description] = true
	}

	for description := range testLogs {
		if !logConfigDescriptions[description] {
			t.Errorf("Test cases exist for non-existent log configuration: %s", description)
		}
	}
}

// TestRegexPerformance tests the performance of regex matching
func TestRegexPerformance(t *testing.T) {
	config := loadDetectorConfig(t)

	for _, logConfig := range config.Logs {
		t.Run(logConfig.Description, func(t *testing.T) {
			regex, err := regexp.Compile(logConfig.Regex)
			if err != nil {
				t.Fatalf("Failed to compile regex: %v", err)
			}

			// Test with a sample log (use first test case if available)
			if tests, exists := testLogs[logConfig.Description]; exists && len(tests) > 0 {
				sampleLog := tests[0].Log

				// Run the regex multiple times to test performance
				for i := 0; i < 1000; i++ {
					regex.FindStringSubmatch(sampleLog)
				}
			}
		})
	}
}

// BenchmarkRegexMatching benchmarks regex matching performance
func BenchmarkRegexMatching(b *testing.B) {
	config := loadDetectorConfig(&testing.T{})

	for _, logConfig := range config.Logs {
		b.Run(logConfig.Description, func(b *testing.B) {
			regex, err := regexp.Compile(logConfig.Regex)
			if err != nil {
				b.Fatalf("Failed to compile regex: %v", err)
			}

			// Use first test case if available
			if tests, exists := testLogs[logConfig.Description]; exists && len(tests) > 0 {
				sampleLog := tests[0].Log

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					regex.FindStringSubmatch(sampleLog)
				}
			}
		})
	}
}
