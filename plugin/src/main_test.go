package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseHookInput(t *testing.T) {
	input := `{
		"session_id": "test-session",
		"tool_name": "Bash",
		"tool_input": {
			"command": "kubectl get pods",
			"description": "List pods"
		},
		"cwd": "/Users/victor/projects/myapp"
	}`

	var hookInput HookInput
	err := json.Unmarshal([]byte(input), &hookInput)
	if err != nil {
		t.Fatalf("Failed to parse input: %v", err)
	}

	if hookInput.ToolName != "Bash" {
		t.Errorf("Expected tool_name 'Bash', got '%s'", hookInput.ToolName)
	}

	if hookInput.WorkingDir != "/Users/victor/projects/myapp" {
		t.Errorf("Expected cwd '/Users/victor/projects/myapp', got '%s'", hookInput.WorkingDir)
	}
}

func TestParseWriteToolInput(t *testing.T) {
	input := `{
		"session_id": "test-session",
		"tool_name": "Write",
		"tool_input": {
			"file_path": "/Users/victor/projects/myapp/src/index.ts",
			"content": "console.log('hello')"
		},
		"cwd": "/Users/victor/projects/myapp"
	}`

	var hookInput HookInput
	err := json.Unmarshal([]byte(input), &hookInput)
	if err != nil {
		t.Fatalf("Failed to parse input: %v", err)
	}

	if hookInput.ToolName != "Write" {
		t.Errorf("Expected tool_name 'Write', got '%s'", hookInput.ToolName)
	}

	// ToolInput is raw JSON now
	if len(hookInput.ToolInput) == 0 {
		t.Error("Expected tool_input to be non-empty")
	}
}

func TestHookOutputFormat(t *testing.T) {
	output := HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision: &Decision{
				Behavior: "allow",
			},
		},
	}

	jsonOut, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal output: %v", err)
	}

	// Verify it contains expected fields
	jsonStr := string(jsonOut)
	if !strings.Contains(jsonStr, `"hookEventName":"PermissionRequest"`) {
		t.Errorf("Output missing hookEventName field: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"behavior":"allow"`) {
		t.Errorf("Output missing behavior field: %s", jsonStr)
	}
}

// Test that the system prompt contains key safety rules
func TestSystemPromptContainsRules(t *testing.T) {
	requiredPatterns := []string{
		"kubectl",
		"gcloud",
		"bq",
		"git push",
		"rm -rf",
		"ALLOW",
		"ASK",
		"Write tool",
		"Edit tool",
		"main/master",
		"feature branches",
	}

	for _, pattern := range requiredPatterns {
		if !strings.Contains(systemPrompt, pattern) {
			t.Errorf("System prompt missing pattern: %s", pattern)
		}
	}
}

func TestGetModel(t *testing.T) {
	// Test default
	if model := getModel(); model != DefaultModel {
		t.Errorf("Expected default model %s, got %s", DefaultModel, model)
	}

	// Test env override
	t.Setenv("ALMOST_YOLO_MODEL", "claude-sonnet-4-20250514")
	if model := getModel(); model != "claude-sonnet-4-20250514" {
		t.Errorf("Expected env model claude-sonnet-4-20250514, got %s", model)
	}
}

func TestShouldSkipEvaluation(t *testing.T) {
	// Tools that should be skipped (no security evaluation needed)
	skipTools := []string{
		"ExitPlanMode", "EnterPlanMode", // Plan mode
		"AskUserQuestion",                                                   // User interaction
		"TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskStop", "TaskOutput", // Task tracking
		"Read", "Glob", "Grep", "WebFetch", "WebSearch", // Read-only
		"Task", "Skill", // Subagent/skill invocation
	}

	for _, tool := range skipTools {
		if !shouldSkipEvaluation(tool) {
			t.Errorf("Expected %s to be skipped, but it wasn't", tool)
		}
	}

	// Tools that should NOT be skipped (need security evaluation)
	evalTools := []string{
		"Bash",         // Shell commands need evaluation
		"Write",        // File creation needs evaluation
		"Edit",         // File modification needs evaluation
		"NotebookEdit", // Notebook changes need evaluation
	}

	for _, tool := range evalTools {
		if shouldSkipEvaluation(tool) {
			t.Errorf("Expected %s to require evaluation, but it was skipped", tool)
		}
	}
}
