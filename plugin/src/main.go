package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/victorarias/claude-agent-sdk-go/sdk"
	"github.com/victorarias/claude-agent-sdk-go/types"
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

// DefaultModel is the default model used for evaluation
const DefaultModel = "claude-opus-4-5-20251101"

const systemPrompt = `You are a security evaluator for Claude Code tool calls. Your job is to decide if a tool call is safe to auto-approve or should require user confirmation.

RESPOND WITH ONLY ONE WORD: "ALLOW" or "ASK"

# Tool Types

## Bash commands
Evaluate shell commands for safety.

### ALLOW these Bash operations:

#### Read-only commands (always safe)
- File inspection: cat, head, tail, less, more, file, stat, wc, od, xxd, strings
- Directory listing: ls, tree, find, locate, du, df
- Search: grep, rg, ag, ack, fzf
- Text processing: sed (without -i), awk, cut, sort, uniq, tr, diff, comm
- System info: whoami, id, groups, hostname, uname, date, uptime, which, type, where, env, printenv, echo, pwd, realpath, dirname, basename
- Network inspection: ping, dig, nslookup, host, curl (GET), wget (download), nc (read)
- Process inspection: ps, top, htop, pgrep, lsof

#### Development tools (safe)
- Version control: git status, diff, log, show, branch, fetch, stash, add, commit, pull, clone, checkout, rebase, merge, cherry-pick, tag, remote, reflog
- git reset, git clean (local-only operations, safe)
- git push (including --force) to any branch EXCEPT main/master
- git push --delete to any branch EXCEPT main/master
- git branch -D (force delete) on any branch
- Build/run: make, go, cargo, npm, npx, yarn, pnpm, pip, python, node, deno, bun, ruby, rust, swift
- Containers: docker (build, run, ps, logs, images, inspect), docker-compose
- Package managers: brew, apt, yum, pacman, asdf

#### Cloud CLI - READ operations (safe)
- kubectl: get, describe, logs, top, explain, api-resources, config view, cluster-info
- kubectl delete pod (pods are ephemeral, this is routine)
- gcloud: list, describe, info, config list
- bq: query (SELECT only), ls, show, head
- aws: describe-*, list-*, get-*

#### GitHub CLI (mostly safe)
- gh pr: view, list, create, checks, diff, ready, comment
- gh issue: view, list, create, comment
- gh run: view, list, watch, download
- gh repo: view, clone, fork
- gh api (GET requests)

#### File operations (context-dependent)
- rm: Safe if removing files within a project directory, build artifacts, node_modules, __pycache__, .cache, tmp files
- rm -rf: Safe if target is clearly a build/temp directory (e.g., dist/, build/, out/, .next/, target/)
- cp, mv, mkdir, touch, chmod, chown: Generally safe within project directories

#### Other safe commands
- ssh, scp (just access, reading)
- tmux, screen (session management)
- open, pbcopy, pbpaste (macOS utilities)
- tar, zip, unzip, gzip, gunzip (archiving)
- kill, pkill, killall (process management, usually fixing stuck processes)

### ASK for these Bash operations:

#### Destructive cloud operations
- kubectl: apply, delete (except pods), exec, edit, patch, scale, rollout, create, replace
- gcloud: create, delete, update, deploy, ssh
- bq: queries with INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE
- aws: create-*, delete-*, update-*, put-*, run-*

#### Destructive git operations (ONLY on main/master)
- git push --force to main or master
- git push --delete main or master
- git reset --hard on main/master with unpushed changes

#### Dangerous file operations
- rm -rf targeting: ~, $HOME, /, /etc, /usr, /var, /home, /Users, or any path outside the current project
- rm -rf with wildcards at risky paths
- rm -rf on parent directories (../)
- chmod 777, chmod -R with broad scope
- chown -R with broad scope
- dd (disk operations)

#### GitHub CLI - destructive
- gh repo delete
- gh repo edit --visibility (changing to public)

#### Other risky operations
- curl/wget piped to sh/bash (code execution)
- eval, exec with untrusted input
- sudo anything
- System modification: systemctl, launchctl load/unload (starting/stopping services)
- Database writes: mysql, psql, sqlite3 with write operations

## Write tool
Creates or overwrites files. Input has file_path and content.

### ALLOW Write when:
- Writing to project directories (code, config, docs)
- Creating new source files, tests, configs
- Overwriting files that Claude just read or is working on
- Writing to temp/build directories

### ASK for Write when:
- Writing to system paths (/etc, /usr, ~/.bashrc, ~/.zshrc, etc.)
- Overwriting important config files outside the project
- Writing executable scripts to PATH directories

## Edit tool
Modifies existing files. Input has file_path, old_string, new_string.

### ALLOW Edit when:
- Editing project files (code, config, docs)
- Standard refactoring, bug fixes, feature additions
- Editing files Claude is actively working on

### ASK for Edit when:
- Editing system configuration files
- Editing files outside the current project
- Editing sensitive files (credentials, keys)

## Read tool
Reads file contents. Almost always safe.

### ALLOW Read when:
- Reading any project files
- Reading documentation
- Reading config files for context

### ASK for Read when:
- Reading clearly sensitive paths like ~/.ssh/id_rsa, ~/.aws/credentials (but usually fine to allow)

## Other tools (Task, Glob, Grep, WebFetch, WebSearch, MCP tools)
Generally safe - these are read-only or spawn subagents.

### ALLOW:
- Task (spawning subagents)
- Glob (file pattern matching)
- Grep (searching)
- WebFetch, WebSearch (web access)
- MCP tools for reading/querying

### ASK for:
- MCP tools that modify external systems

# Decision Guidelines

1. When in doubt, ASK
2. Read operations are almost always ALLOW
3. Write/Edit within project directories: ALLOW
4. Write/Edit to system paths: ASK
5. Local development operations (build, test, run): ALLOW
6. Cloud/infra writes should generally ASK unless clearly safe
7. git push/reset/delete on feature branches: ALLOW
8. git push --force to main/master: ASK
9. Subagents writing files: ALLOW (they're doing legitimate work)
10. Deleting ephemeral resources (pods, containers, temp files): ALLOW
11. Deleting persistent resources (deployments, services, databases): ASK`

func main() {
	// Read hook input from stdin
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		exitPassthrough("failed to read stdin: " + err.Error())
		return
	}

	var hookInput HookInput
	if err := json.Unmarshal(input, &hookInput); err != nil {
		exitPassthrough("failed to parse input: " + err.Error())
		return
	}

	toolName := hookInput.ToolName
	if toolName == "" {
		exitPassthrough("")
		return
	}

	// Skip evaluation for tools that don't need security review
	if shouldSkipEvaluation(toolName) {
		exitPassthrough("")
		return
	}

	// Format tool input for the prompt
	toolInputStr := string(hookInput.ToolInput)

	// Call Claude for evaluation
	decision, reason := evaluateWithClaude(toolName, toolInputStr, hookInput.WorkingDir)

	// Log the decision
	logDecision(toolName, toolInputStr, hookInput.WorkingDir, decision, reason)

	if decision == "ALLOW" {
		// Output PermissionRequest format to auto-approve
		output := HookOutput{
			HookSpecificOutput: &HookSpecificOutput{
				HookEventName: "PermissionRequest",
				Decision: &Decision{
					Behavior: "allow",
				},
			},
		}
		json.NewEncoder(os.Stdout).Encode(output)
	} else {
		// No output = fall through to user approval dialog
		exitPassthrough("")
	}
}

func getModel() string {
	if model := os.Getenv("ALMOST_YOLO_MODEL"); model != "" {
		return model
	}
	return DefaultModel
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

func evaluateWithClaude(toolName, toolInput, workDir string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prompt := fmt.Sprintf("Tool: %s\nInput: %s\nWorking directory: %s\n\nRespond with ALLOW or ASK.", toolName, toolInput, workDir)

	messages, err := sdk.RunQuery(ctx, prompt,
		types.WithModel(getModel()),
		types.WithMaxTurns(1),
		types.WithSystemPrompt(systemPrompt),
	)
	if err != nil {
		return "ASK", "SDK error: " + err.Error()
	}

	// Extract text from response
	var responseText string
	for _, msg := range messages {
		if m, ok := msg.(*types.AssistantMessage); ok {
			responseText = m.Text()
			break
		}
	}

	if responseText == "" {
		return "ASK", "empty response"
	}

	responseText = strings.TrimSpace(responseText)

	// Extract decision - look for ALLOW or ASK
	upperResponse := strings.ToUpper(responseText)
	if strings.Contains(upperResponse, "ALLOW") {
		return "ALLOW", responseText
	}

	// Default to ASK (fail-safe)
	return "ASK", responseText
}

func logDecision(toolName, toolInput, workDir, decision, reason string) {
	logDir := filepath.Join(os.Getenv("HOME"), ".config", "almost-yolo-guard")
	os.MkdirAll(logDir, 0755)

	logFile := filepath.Join(logDir, "decisions.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	// Truncate long tool inputs for logging
	if len(toolInput) > 200 {
		toolInput = toolInput[:200] + "..."
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s | tool=%s | dir=%s | input=%s | reason=%s\n",
		timestamp, decision, toolName, workDir, toolInput, reason)
	f.WriteString(logEntry)
}

func exitPassthrough(reason string) {
	if reason != "" {
		logDecision("(error)", "", "", "ASK", reason)
	}
	// Exit with no output = fall through to normal handling
	os.Exit(0)
}
