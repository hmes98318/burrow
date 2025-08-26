package shared

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
)

// Generates a random token for detector authentication
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Checks if the given string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Extracts IP address from log line using regex
func ExtractIPFromLog(logLine, regexPattern string) (string, error) {
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", err
	}

	matches := re.FindStringSubmatch(logLine)
	if len(matches) < 2 {
		return "", nil
	}

	// Find the first valid IP in the matches
	for i := 1; i < len(matches); i++ {
		if IsValidIP(strings.TrimSpace(matches[i])) {
			return strings.TrimSpace(matches[i]), nil
		}
	}

	return "", nil
}

// Removes invalid characters from filename
func SanitizeFilename(filename string) string {
	// Replace invalid characters with underscore
	re := regexp.MustCompile(`[<>:"/\\|?*]`)
	return re.ReplaceAllString(filename, "_")
}

// Processes placeholders in regex patterns
// Replaces {{ placeholder_key }} with corresponding values from placeholders map
// If placeholder not found, keeps the original {{ placeholder_key }} and logs warning
func ProcessPlaceholders(text string, placeholders map[string]string) string {
	// Regular expression to match {{ placeholder_key }} with optional spaces
	placeholderRegex := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*\}\}`)

	// Find all placeholders in the text
	matches := placeholderRegex.FindAllStringSubmatch(text, -1)

	result := text
	for _, match := range matches {
		if len(match) >= 2 {
			fullMatch := match[0]      // Complete {{ placeholder_key }}
			placeholderKey := match[1] // Just the key without {{ }}

			// Check if placeholder exists
			if value, exists := placeholders[placeholderKey]; exists {
				// Replace the placeholder with its value
				result = strings.ReplaceAll(result, fullMatch, value)
			} else {
				// Log warning if placeholder not found
				log.Printf("Warning: Placeholder '%s' not found in placeholders map, keeping original text", placeholderKey)
			}
		}
	}

	return result
}

// Validates that all placeholders in logs can be resolved
// Returns error with details of missing placeholders
func ValidatePlaceholders(logs []LogConfig, placeholders map[string]string) error {
	placeholderRegex := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*\}\}`)
	var missingPlaceholders []string

	for i, logConfig := range logs {
		matches := placeholderRegex.FindAllStringSubmatch(logConfig.Regex, -1)

		for _, match := range matches {
			if len(match) >= 2 {
				placeholderKey := match[1]
				if _, exists := placeholders[placeholderKey]; !exists {
					missingPlaceholder := fmt.Sprintf("log[%d]: missing placeholder '%s'", i, placeholderKey)
					missingPlaceholders = append(missingPlaceholders, missingPlaceholder)
				}
			}
		}
	}

	if len(missingPlaceholders) > 0 {
		return fmt.Errorf("missing placeholders found:\n%s", strings.Join(missingPlaceholders, "\n"))
	}

	return nil
}
