package main

import (
	"testing"
)

func TestParseDecision(t *testing.T) {
	tests := []struct {
		response string
		want     string
	}{
		{"ALLOW", "ALLOW"},
		{"ASK", "ASK"},
		{"allow", "ALLOW"},
		{"ask", "ASK"},
		{"ALLOW - this is a read-only command", "ALLOW"},
		{"ASK - this modifies infrastructure", "ASK"},
		{"I would say ALLOW since this is safe", "ALLOW"},
		{"This should ASK the user", "ASK"},
		{"", "ASK"},           // empty = fail-safe
		{"maybe", "ASK"},      // unclear = fail-safe
		{"not sure", "ASK"},   // unclear = fail-safe
		{"definitely", "ASK"}, // no ALLOW keyword = fail-safe
		{"ALLOW\n\nThis is safe.", "ALLOW"},
		{"  ALLOW  ", "ALLOW"},
		{"  ASK  ", "ASK"},
	}

	for _, tt := range tests {
		t.Run(tt.response, func(t *testing.T) {
			got := ParseDecision(tt.response)
			if got != tt.want {
				t.Errorf("ParseDecision(%q) = %q, want %q", tt.response, got, tt.want)
			}
		})
	}
}

func TestFormatPrompt(t *testing.T) {
	prompt := FormatPrompt("Bash", `{"command":"ls"}`, "/proj")

	// Verify it contains the key parts
	if got := prompt; got == "" {
		t.Fatal("FormatPrompt returned empty string")
	}

	mustContain := []string{"Bash", `{"command":"ls"}`, "/proj", "ALLOW", "ASK"}
	for _, s := range mustContain {
		if !containsString(prompt, s) {
			t.Errorf("FormatPrompt missing %q in:\n%s", s, prompt)
		}
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		findSubstring(haystack, needle))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
