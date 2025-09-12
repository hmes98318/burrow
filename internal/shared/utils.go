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

// Processes placeholders in regex patterns with support for nested placeholders
// Replaces {{ placeholder_key }} with corresponding values from placeholders map
// Supports nested placeholders by processing recursively until no more placeholders are found
// If placeholder not found, keeps the original {{ placeholder_key }} and logs warning
func ProcessPlaceholders(text string, placeholders map[string]string) string {
	// Create a processed placeholders map to avoid infinite recursion
	processedPlaceholders := make(map[string]string)

	// First, process all placeholders to resolve nested ones
	for key, value := range placeholders {
		processedPlaceholders[key] = processPlaceholdersRecursive(value, placeholders, make(map[string]bool), 10)
	}

	// Now process the input text with the resolved placeholders
	return processPlaceholdersRecursive(text, processedPlaceholders, make(map[string]bool), 10)
}

// Recursive function to process placeholders with cycle detection and max depth limit
func processPlaceholdersRecursive(text string, placeholders map[string]string, processing map[string]bool, maxDepth int) string {
	if maxDepth <= 0 {
		log.Printf("Warning: Maximum recursion depth reached while processing placeholders")
		return text
	}

	// Regular expression to match {{ placeholder_key }} with optional spaces
	placeholderRegex := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*\}\}`)

	// Check if text contains any placeholders
	if !placeholderRegex.MatchString(text) {
		return text
	}

	// Find all placeholders in the text
	matches := placeholderRegex.FindAllStringSubmatch(text, -1)
	hasReplacements := false

	result := text
	for _, match := range matches {
		if len(match) >= 2 {
			fullMatch := match[0]      // Complete {{ placeholder_key }}
			placeholderKey := match[1] // Just the key without {{ }}

			// Check for circular reference
			if processing[placeholderKey] {
				log.Printf("Warning: Circular reference detected for placeholder '%s', skipping", placeholderKey)
				continue
			}

			// Check if placeholder exists
			if value, exists := placeholders[placeholderKey]; exists {
				// Mark as being processed to detect cycles
				processing[placeholderKey] = true

				// Recursively process the placeholder value
				processedValue := processPlaceholdersRecursive(value, placeholders, processing, maxDepth-1)

				// Replace the placeholder with its processed value
				result = strings.ReplaceAll(result, fullMatch, processedValue)
				hasReplacements = true

				// Remove from processing map
				delete(processing, placeholderKey)
			} else {
				// Log warning if placeholder not found
				log.Printf("Warning: Placeholder '%s' not found in placeholders map, keeping original text", placeholderKey)
			}
		}
	}

	// If we made replacements and there might be more placeholders to process, recurse
	// BUT stop if we detect we're in a self-referencing scenario
	if hasReplacements && placeholderRegex.MatchString(result) {
		// Check if the result is getting longer due to self-reference expansion
		// If so, we should stop to prevent infinite expansion
		if len(result) > len(text)*2 {
			log.Printf("Warning: Potential self-reference expansion detected, stopping further processing")
			return result
		}
		return processPlaceholdersRecursive(result, placeholders, processing, maxDepth-1)
	}

	return result
}

// Validates that all placeholders in logs can be resolved, including nested placeholders
// Returns error with details of missing placeholders
func ValidatePlaceholders(logs []LogConfig, placeholders map[string]string) error {
	var missingPlaceholders []string

	// First, validate that all placeholders used in placeholder definitions exist
	for key, value := range placeholders {
		missing := validatePlaceholdersInText(value, placeholders, fmt.Sprintf("placeholder '%s'", key))
		missingPlaceholders = append(missingPlaceholders, missing...)
	}

	// Then validate placeholders in log configurations
	for i, logConfig := range logs {
		missing := validatePlaceholdersInText(logConfig.Regex, placeholders, fmt.Sprintf("log[%d]", i))
		missingPlaceholders = append(missingPlaceholders, missing...)
	}

	if len(missingPlaceholders) > 0 {
		return fmt.Errorf("missing placeholders found:\n%s", strings.Join(missingPlaceholders, "\n"))
	}

	return nil
}

// Helper function to validate placeholders in a given text
func validatePlaceholdersInText(text string, placeholders map[string]string, context string) []string {
	placeholderRegex := regexp.MustCompile(`\{\{\s*([^}\s]+)\s*\}\}`)
	var missingPlaceholders []string
	visited := make(map[string]bool)

	matches := placeholderRegex.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			placeholderKey := match[1]
			if !visited[placeholderKey] {
				visited[placeholderKey] = true
				if _, exists := placeholders[placeholderKey]; !exists {
					missingPlaceholder := fmt.Sprintf("%s: missing placeholder '%s'", context, placeholderKey)
					missingPlaceholders = append(missingPlaceholders, missingPlaceholder)
				}
			}
		}
	}

	return missingPlaceholders
}
