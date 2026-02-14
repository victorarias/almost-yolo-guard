package main

import (
	"encoding/json"
	"io"
	"os"
)

// HookInput matches Claude Code's PermissionRequest hook input
type HookInput struct {
	SessionID  string          `json:"session_id"`
	ToolName   string          `json:"tool_name"`
	ToolInput  json.RawMessage `json:"tool_input"`
	WorkingDir string          `json:"cwd"`
}

// HookOutput for PermissionRequest uses hookSpecificOutput format
type HookOutput struct {
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type HookSpecificOutput struct {
	HookEventName string    `json:"hookEventName"`
	Decision      *Decision `json:"decision,omitempty"`
}

type Decision struct {
	Behavior string `json:"behavior"` // "allow" or "deny"
	Message  string `json:"message,omitempty"`
}

// skipEvaluationTools contains tools that don't need security evaluation.
// These are either read-only, user-facing, or internal tracking tools.
var skipEvaluationTools = map[string]bool{
	// Plan mode - separate UX flow for plan approval
	"ExitPlanMode":  true,
	"EnterPlanMode": true,

	// User interaction - just prompts the user
	"AskUserQuestion": true,

	// Task tracking - internal state management
	"TaskCreate": true,
	"TaskUpdate": true,
	"TaskList":   true,
	"TaskGet":    true,
	"TaskStop":   true,
	"TaskOutput": true,

	// Read-only tools - no side effects
	"Read":      true,
	"Glob":      true,
	"Grep":      true,
	"WebFetch":  true,
	"WebSearch": true,

	// Subagent/skill invocation - spawns isolated work
	"Task":  true,
	"Skill": true,
}

func shouldSkipEvaluation(toolName string) bool {
	return skipEvaluationTools[toolName]
}

func readHookInput() (*HookInput, error) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	var hookInput HookInput
	if err := json.Unmarshal(input, &hookInput); err != nil {
		return nil, err
	}
	return &hookInput, nil
}

func writeAllowOutput() {
	output := HookOutput{
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision: &Decision{
				Behavior: "allow",
			},
		},
	}
	json.NewEncoder(os.Stdout).Encode(output)
}

func exitPassthrough(reason string) {
	if reason != "" {
		logDecision("(error)", "", "", "ASK", "passthrough", reason)
	}
	// Exit with no output = fall through to normal handling
	os.Exit(0)
}
