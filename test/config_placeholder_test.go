package test

import (
	"testing"

	"malicious-detector/internal/shared"
)

func TestProcessPlaceholders(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		placeholders map[string]string
		expected     string
	}{
		{
			name: "simple placeholder replacement",
			text: "Failed password for .+ from {{ ip_regex }}",
			placeholders: map[string]string{
				"ip_regex": "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
			},
			expected: "Failed password for .+ from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
		},
		{
			name: "multiple placeholders",
			text: "{{ ip_regex }} .+ \"{{ http_method_regex }} /admin",
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expected: "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}) .+ \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) /admin",
		},
		{
			name: "placeholder with spaces",
			text: "Failed from {{  ipv4_regex  }}",
			placeholders: map[string]string{
				"ipv4_regex": "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
			},
			expected: "Failed from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
		},
		{
			name: "IPv6 placeholder test",
			text: "IPv6 connection from {{ ipv6_regex }}",
			placeholders: map[string]string{
				"ipv6_regex": "((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
			},
			expected: "IPv6 connection from ((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
		},
		{
			name: "missing placeholder (should keep original)",
			text: "Failed from {{ missing_regex }}",
			placeholders: map[string]string{
				"ip_regex": "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
			},
			expected: "Failed from {{ missing_regex }}",
		},
		{
			name: "no placeholders",
			text: "Failed password for .+ from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
			placeholders: map[string]string{
				"ipv4_regex": "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
			},
			expected: "Failed password for .+ from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
		},
		{
			name: "real world SSH brute force pattern",
			text: "Failed password for .+ from {{ ip_regex }}",
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"ipv4_regex":        "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
				"ipv6_regex":        "((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expected: "Failed password for .+ from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
		},
		{
			name: "real world Nginx vulnerability scanning pattern",
			text: "{{ ip_regex }} .+ \"{{ http_method_regex }} \\/\\.?(?:env|git|admin|wp-admin|phpmyadmin)",
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expected: "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}) .+ \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) \\/\\.?(?:env|git|admin|wp-admin|phpmyadmin)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shared.ProcessPlaceholders(tt.text, tt.placeholders)
			if result != tt.expected {
				t.Errorf("ProcessPlaceholders() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestValidatePlaceholders(t *testing.T) {
	tests := []struct {
		name         string
		logs         []shared.LogConfig
		placeholders map[string]string
		expectError  bool
	}{
		{
			name: "all placeholders exist",
			logs: []shared.LogConfig{
				{Regex: "Failed from {{ ip_regex }}"},
				{Regex: "Method {{ http_method_regex }} from {{ ipv4_regex }}"},
				{Regex: "IPv6 from {{ ipv6_regex }}"},
			},
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"ipv4_regex":        "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
				"ipv6_regex":        "((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expectError: false,
		},
		{
			name: "missing placeholder",
			logs: []shared.LogConfig{
				{Regex: "Failed from {{ missing_regex }}"},
			},
			placeholders: map[string]string{
				"ip_regex":   "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"ipv4_regex": "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
			},
			expectError: true,
		},
		{
			name: "no placeholders used",
			logs: []shared.LogConfig{
				{Regex: "Failed from ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"},
			},
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"ipv4_regex":        "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
				"ipv6_regex":        "((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expectError: false,
		},
		{
			name: "real world SSH and web patterns",
			logs: []shared.LogConfig{
				{Regex: "Failed password for .+ from {{ ip_regex }}"},
				{Regex: "{{ ip_regex }} .+ \"{{ http_method_regex }} \\/\\.?(?:env|git|admin|wp-admin|phpmyadmin)"},
				{Regex: "FAIL LOGIN: Client \"{{ ip_regex }}\""},
			},
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"ipv4_regex":        "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))",
				"ipv6_regex":        "((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expectError: false,
		},
		{
			name: "partial placeholders missing",
			logs: []shared.LogConfig{
				{Regex: "{{ ip_regex }} .+ \"{{ http_method_regex }} /admin"},
				{Regex: "Connection from {{ unknown_placeholder }}"},
			},
			placeholders: map[string]string{
				"ip_regex":          "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})",
				"http_method_regex": "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := shared.ValidatePlaceholders(tt.logs, tt.placeholders)
			if tt.expectError && err == nil {
				t.Errorf("ValidatePlaceholders() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("ValidatePlaceholders() unexpected error: %v", err)
			}
		})
	}
}

// Nested Placeholder Tests
func TestNestedPlaceholders(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		placeholders map[string]string
		expected     string
		description  string
	}{
		{
			name: "simple nested placeholder",
			text: "Pattern: {{ combined_pattern }}",
			placeholders: map[string]string{
				"ip_regex":         "(\\d+\\.\\d+\\.\\d+\\.\\d+)",
				"method_regex":     "(GET|POST)",
				"combined_pattern": "{{ ip_regex }} .+ \"{{ method_regex }}",
			},
			expected:    "Pattern: (\\d+\\.\\d+\\.\\d+\\.\\d+) .+ \"(GET|POST)",
			description: "Basic nested placeholder replacement",
		},
		{
			name: "deep nested placeholder",
			text: "Deep pattern: {{ level3 }}",
			placeholders: map[string]string{
				"base":   "\\d+",
				"level1": "{{ base }}\\.\\d+",
				"level2": "{{ level1 }}\\.\\d+",
				"level3": "{{ level2 }}\\.\\d+",
			},
			expected:    "Deep pattern: \\d+\\.\\d+\\.\\d+\\.\\d+",
			description: "Three levels of nested placeholders",
		},
		{
			name: "multiple nested placeholders in one text",
			text: "{{ pattern1 }} and {{ pattern2 }}",
			placeholders: map[string]string{
				"ip":       "\\d+\\.\\d+\\.\\d+\\.\\d+",
				"method":   "GET|POST",
				"pattern1": "IP: {{ ip }}",
				"pattern2": "Method: {{ method }}",
			},
			expected:    "IP: \\d+\\.\\d+\\.\\d+\\.\\d+ and Method: GET|POST",
			description: "Multiple nested placeholders in same text",
		},
		{
			name: "nested placeholder with missing dependency",
			text: "Pattern: {{ broken_pattern }}",
			placeholders: map[string]string{
				"broken_pattern": "{{ missing_placeholder }} test",
			},
			expected:    "Pattern: {{ missing_placeholder }} test",
			description: "Should keep unresolved placeholder when dependency missing",
		},
		{
			name: "complex real-world nginx security pattern",
			text: "{{ ip_regex }} .+ \".*{{ nginx_security_regex }}",
			placeholders: map[string]string{
				"ip_regex":                "(\\d+\\.\\d+\\.\\d+\\.\\d+)",
				"vuln_scan_regex":         "/\\.?(?:env|git|admin|wp-admin|phpmyadmin)",
				"command_injection_regex": "(?:nslookup|curl|echo|wget|ping)\\s",
				"shell_injection_regex":   "(?:\\$\\(|\\|\\||&&|;|`)",
				"dns_exfiltration_regex":  "\\.(?:bxss\\.me|dnslog\\.)",
				"nginx_security_regex":    "(?:{{ vuln_scan_regex }}|{{ command_injection_regex }}|{{ shell_injection_regex }}|{{ dns_exfiltration_regex }})",
			},
			expected:    "(\\d+\\.\\d+\\.\\d+\\.\\d+) .+ \".*(?:/\\.?(?:env|git|admin|wp-admin|phpmyadmin)|(?:nslookup|curl|echo|wget|ping)\\s|(?:\\$\\(|\\|\\||&&|;|`)|\\.(?:bxss\\.me|dnslog\\.))",
			description: "Real-world nginx security pattern with multiple nested placeholders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shared.ProcessPlaceholders(tt.text, tt.placeholders)
			if result != tt.expected {
				t.Errorf("ProcessPlaceholders() = %v, want %v", result, tt.expected)
				t.Errorf("Description: %s", tt.description)
			}
		})
	}
}

func TestNestedPlaceholderValidation(t *testing.T) {
	tests := []struct {
		name         string
		logs         []shared.LogConfig
		placeholders map[string]string
		expectError  bool
		description  string
	}{
		{
			name: "valid nested placeholders",
			logs: []shared.LogConfig{
				{Regex: "{{ ip_regex }} .+ \".*{{ nginx_security_regex }}"},
			},
			placeholders: map[string]string{
				"ip_regex":             "(\\d+\\.\\d+\\.\\d+\\.\\d+)",
				"command_regex":        "(?:curl|wget)",
				"nginx_security_regex": "{{ command_regex }}\\s",
			},
			expectError: false,
			description: "Should validate successfully with nested placeholders",
		},
		{
			name: "missing nested placeholder dependency",
			logs: []shared.LogConfig{
				{Regex: "{{ ip_regex }} .+ \".*{{ nginx_security_regex }}"},
			},
			placeholders: map[string]string{
				"ip_regex":             "(\\d+\\.\\d+\\.\\d+\\.\\d+)",
				"nginx_security_regex": "{{ missing_command_regex }}\\s",
			},
			expectError: true,
			description: "Should fail validation when nested placeholder dependency is missing",
		},
		{
			name: "missing root placeholder",
			logs: []shared.LogConfig{
				{Regex: "{{ missing_root }} .+ test"},
			},
			placeholders: map[string]string{
				"some_other_regex": "test",
			},
			expectError: true,
			description: "Should fail validation when root placeholder is missing",
		},
		{
			name: "complex nested validation",
			logs: []shared.LogConfig{
				{Regex: "{{ enhanced_security_regex }}"},
			},
			placeholders: map[string]string{
				"ip_regex":                "(\\d+\\.\\d+\\.\\d+\\.\\d+)",
				"vuln_scan_paths":         "/\\.?(?:env|git|admin)",
				"command_injection":       "(?:curl|wget)\\s",
				"web_attack_patterns":     "(?:{{ vuln_scan_paths }}|{{ command_injection }})",
				"enhanced_security_regex": "{{ ip_regex }} .+ \".*{{ web_attack_patterns }}",
			},
			expectError: false,
			description: "Should validate complex multi-level nested placeholders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := shared.ValidatePlaceholders(tt.logs, tt.placeholders)
			hasError := err != nil

			if hasError != tt.expectError {
				if tt.expectError {
					t.Errorf("ValidatePlaceholders() expected error but got none")
				} else {
					t.Errorf("ValidatePlaceholders() unexpected error: %v", err)
				}
				t.Errorf("Description: %s", tt.description)
			}
		})
	}
}

func TestCircularReferenceDetection(t *testing.T) {
	tests := []struct {
		name             string
		text             string
		placeholders     map[string]string
		expectedContains string
		description      string
	}{
		{
			name: "direct circular reference",
			text: "{{ circular }}",
			placeholders: map[string]string{
				"circular": "{{ circular }}",
			},
			expectedContains: "{{ circular }}",
			description:      "Should detect direct circular reference and stop",
		},
		{
			name: "indirect circular reference",
			text: "{{ a }}",
			placeholders: map[string]string{
				"a": "{{ b }}",
				"b": "{{ c }}",
				"c": "{{ a }}",
			},
			expectedContains: "{{ a }}",
			description:      "Should detect indirect circular reference",
		},
		{
			name: "valid complex nesting without circles",
			text: "{{ complex }}",
			placeholders: map[string]string{
				"base":    "test",
				"level1":  "{{ base }}_1",
				"level2":  "{{ level1 }}_2",
				"complex": "prefix_{{ level2 }}_suffix",
			},
			expectedContains: "prefix_test_1_2_suffix",
			description:      "Should handle complex valid nesting without issues",
		},
		{
			name: "self-referencing with additional content",
			text: "{{ pattern }}",
			placeholders: map[string]string{
				"pattern": "start_{{ pattern }}_end",
			},
			expectedContains: "start_start_start_start_start_start_start_start_start_start_start_{{ pattern }}_end_end_end_end_end_end_end_end_end_end_end",
			description:      "Should detect self-reference with additional content",
		},
		{
			name: "depth limit test",
			text: "{{ level10 }}",
			placeholders: map[string]string{
				"level1":  "{{ base }}_1",
				"level2":  "{{ level1 }}_2",
				"level3":  "{{ level2 }}_3",
				"level4":  "{{ level3 }}_4",
				"level5":  "{{ level4 }}_5",
				"level6":  "{{ level5 }}_6",
				"level7":  "{{ level6 }}_7",
				"level8":  "{{ level7 }}_8",
				"level9":  "{{ level8 }}_9",
				"level10": "{{ level9 }}_10",
				"level11": "{{ level10 }}_11",
				"base":    "start",
			},
			expectedContains: "start_1_2_3_4_5_6_7_8_9_10",
			description:      "Should handle 10 levels of nesting correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shared.ProcessPlaceholders(tt.text, tt.placeholders)
			if result != tt.expectedContains {
				t.Errorf("ProcessPlaceholders() = %v, want %v", result, tt.expectedContains)
				t.Errorf("Description: %s", tt.description)
			}
		})
	}
}
