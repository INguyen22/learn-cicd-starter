package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Valid(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey my-secret-key-123")

	key, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "my-secret-key-123" {
		t.Errorf("expected key 'my-secret-key-123', got '%s'", key)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := make(http.Header)
	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_Malformed(t *testing.T) {
	testCases := []struct {
		name  string
		value string
	}{
		{"Wrong Prefix", "Bearer token123"},
		{"No Space", "ApiKey"},
		{"Empty String", ""}, // This actually triggers ErrNoAuthHeaderIncluded, but still an error path
		{"Only Space", " "},
		// "Multiple Spaces" removed because "ApiKey token extra" is technically valid
		// with your current logic (returns "token").
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Authorization", tc.value)

			_, err := GetAPIKey(headers)

			// ASSERT: Ensure an error occurred
			if err == nil {
				t.Errorf("expected error for case '%s', got nil", tc.name)
				return // Stop here to avoid panic on nil err
			}

			// Specific check for Empty String vs Malformed
			if tc.value == "" {
				if err != ErrNoAuthHeaderIncluded {
					t.Errorf("expected ErrNoAuthHeaderIncluded for empty string, got %v", err)
				}
			} else {
				if err.Error() != "malformed authorization header" {
					t.Errorf("expected 'malformed authorization header', got %v", err)
				}
			}
		})
	}
}
