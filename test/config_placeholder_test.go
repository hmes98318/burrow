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
