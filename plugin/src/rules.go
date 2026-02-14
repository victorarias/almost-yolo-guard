package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// EvaluateRules applies deterministic rules to decide if a tool call is safe.
// Returns VerdictAllow, VerdictAsk, or VerdictUncertain.
func EvaluateRules(toolName string, toolInput json.RawMessage, workDir string) (Verdict, string) {
	switch toolName {
	case "Bash":
		return evaluateBash(toolInput, workDir)
	case "Write", "Edit", "NotebookEdit":
		return evaluateFileOp(toolName, toolInput, workDir)
	default:
		return VerdictUncertain, "unknown tool: " + toolName
	}
}

// --- Bash evaluation ---

func evaluateBash(toolInput json.RawMessage, workDir string) (Verdict, string) {
	var input struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return VerdictUncertain, "failed to parse command"
	}

	command := strings.TrimSpace(input.Command)
	if command == "" {
		return VerdictUncertain, "empty command"
	}

	return evaluateCommand(command, workDir)
}

func evaluateCommand(command, workDir string) (Verdict, string) {
	segments := splitCompoundCommand(command)

	worstVerdict := VerdictAllow
	var worstReason string

	for i, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}

		// Check for pipe-to-shell pattern (curl ... | bash)
		if i > 0 && isPipeToShell(seg) {
			return VerdictAsk, "pipe to shell interpreter: " + seg
		}

		verdict, reason := evaluateSegment(seg, workDir)
		if verdict > worstVerdict {
			worstVerdict = verdict
			worstReason = reason
		}
	}

	return worstVerdict, worstReason
}

// splitCompoundCommand splits on &&, ||, ;, and | while respecting quotes.
func splitCompoundCommand(command string) []string {
	var segments []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		if ch == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(ch)
			continue
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteRune(ch)
			continue
		}

		if inSingleQuote || inDoubleQuote {
			current.WriteRune(ch)
			continue
		}

		// Split on && (skip second &)
		if ch == '&' && i+1 < len(runes) && runes[i+1] == '&' {
			segments = append(segments, current.String())
			current.Reset()
			i++
			continue
		}
		// Split on || (skip second |)
		if ch == '|' && i+1 < len(runes) && runes[i+1] == '|' {
			segments = append(segments, current.String())
			current.Reset()
			i++
			continue
		}
		// Split on single |
		if ch == '|' {
			segments = append(segments, current.String())
			current.Reset()
			continue
		}
		// Split on ;
		if ch == ';' {
			segments = append(segments, current.String())
			current.Reset()
			continue
		}

		current.WriteRune(ch)
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

func isPipeToShell(segment string) bool {
	cmd := extractBaseCommand(strings.TrimSpace(segment))
	switch cmd {
	case "bash", "sh", "zsh", "fish",
		"python", "python3", "perl", "ruby", "node":
		return true
	}
	return false
}

// extractBaseCommand gets the first command word, stripping env var prefixes and paths.
func extractBaseCommand(segment string) string {
	words := strings.Fields(segment)
	if len(words) == 0 {
		return ""
	}

	// Skip leading env var assignments (FOO=bar cmd)
	startIdx := 0
	for i, w := range words {
		if !strings.Contains(w, "=") || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") || strings.HasPrefix(w, ".") {
			startIdx = i
			break
		}
		if i == len(words)-1 {
			return "" // all words are assignments
		}
	}
	words = words[startIdx:]

	if len(words) == 0 {
		return ""
	}

	// Handle 'env' prefix
	if words[0] == "env" {
		for i := 1; i < len(words); i++ {
			if !strings.Contains(words[i], "=") {
				return filepath.Base(words[i])
			}
		}
		return ""
	}

	return filepath.Base(words[0])
}

// extractArgs returns everything after the base command.
func extractArgs(segment string) []string {
	words := strings.Fields(segment)
	if len(words) == 0 {
		return nil
	}

	// Skip env var assignments
	startIdx := 0
	for i, w := range words {
		if !strings.Contains(w, "=") || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") || strings.HasPrefix(w, ".") {
			startIdx = i
			break
		}
		if i == len(words)-1 {
			return nil
		}
	}

	// Handle 'env' prefix
	if words[startIdx] == "env" {
		for i := startIdx + 1; i < len(words); i++ {
			if !strings.Contains(words[i], "=") {
				if i+1 < len(words) {
					return words[i+1:]
				}
				return nil
			}
		}
		return nil
	}

	if startIdx+1 < len(words) {
		return words[startIdx+1:]
	}
	return nil
}

func evaluateSegment(segment string, workDir string) (Verdict, string) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return VerdictAllow, ""
	}

	baseCmd := extractBaseCommand(segment)
	if baseCmd == "" {
		return VerdictUncertain, "could not extract command"
	}

	args := extractArgs(segment)

	// Always ask
	if isAlwaysAsk(baseCmd) {
		return VerdictAsk, "dangerous command: " + baseCmd
	}

	// Always safe (regardless of args)
	if isAlwaysSafe(baseCmd) {
		return VerdictAllow, "safe command: " + baseCmd
	}

	// Special handling
	switch baseCmd {
	case "git":
		return evaluateGit(args)
	case "kubectl":
		return evaluateKubectl(args)
	case "rm":
		return evaluateRm(args, workDir)
	case "chmod":
		return evaluateChmod(args)
	case "chown":
		return evaluateChown(args)
	case "gh":
		return evaluateGh(args)
	case "gcloud":
		return evaluateGcloud(args)
	case "bq":
		return evaluateBq(args)
	case "aws":
		return evaluateAws(args)
	case "sed":
		return evaluateSed(args)
	case "curl", "wget":
		// Not piped to shell (that's caught earlier), so safe
		return VerdictAllow, baseCmd + " (not piped to shell)"
	case "kill", "pkill", "killall":
		return VerdictAllow, "process management"
	case "cp", "mv", "mkdir", "touch":
		return evaluateFileCmd(baseCmd, args, workDir)
	case "ssh":
		return evaluateSSH(args)
	case "scp":
		return VerdictUncertain, "scp (remote file transfer)"
	case "docker", "podman":
		return evaluateDocker(args)
	case "docker-compose":
		return evaluateDockerCompose(args)
	case "npm", "yarn", "pnpm":
		return evaluateNodePkgMgr(baseCmd, args)
	case "npx":
		return VerdictUncertain, "npx downloads and runs code"
	case "pip", "pip3":
		return evaluatePip(baseCmd, args)
	case "python", "python3", "node", "deno", "bun", "ruby", "swift":
		return evaluateRuntime(baseCmd, args)
	case "go":
		return evaluateGo(args)
	case "cargo":
		return evaluateCargo(args)
	case "helm":
		return evaluateHelm(args)
	case "find":
		return evaluateFind(args)
	case "tee":
		return evaluateTee(args, workDir)
	case "nc":
		return VerdictUncertain, "netcat"
	case "xargs":
		return VerdictUncertain, "xargs executes commands"
	case "yes":
		return VerdictUncertain, "yes auto-confirms prompts"
	case "nohup", "time":
		if len(args) == 0 {
			return VerdictUncertain, baseCmd + " (no command)"
		}
		return evaluateCommand(strings.Join(args, " "), workDir)
	case "timeout":
		return evaluateTimeout(args, workDir)
	case "brew", "apt", "apt-get", "yum", "pacman":
		return evaluatePackageManager(baseCmd, args)
	}

	// Unknown command
	return VerdictUncertain, "unknown command: " + baseCmd
}

// --- Command classification ---

var alwaysSafeCommands = map[string]bool{
	// File inspection
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"file": true, "stat": true, "wc": true, "od": true, "xxd": true, "strings": true,
	// Directory listing
	"ls": true, "tree": true, "locate": true, "du": true, "df": true,
	// Search
	"grep": true, "rg": true, "ag": true, "ack": true, "fzf": true,
	// Text processing
	"awk": true, "cut": true, "sort": true, "uniq": true, "tr": true,
	"diff": true, "comm": true, "jq": true, "yq": true,
	// System info
	"whoami": true, "id": true, "groups": true, "hostname": true, "uname": true,
	"date": true, "uptime": true, "which": true, "type": true, "where": true,
	"env": true, "printenv": true, "echo": true, "printf": true, "pwd": true,
	"realpath": true, "dirname": true, "basename": true, "true": true, "false": true,
	"test": true, "[": true,
	// Network inspection
	"ping": true, "dig": true, "nslookup": true, "host": true,
	// Process inspection
	"ps": true, "top": true, "htop": true, "pgrep": true, "lsof": true,
	// Archive
	"tar": true, "zip": true, "unzip": true, "gzip": true, "gunzip": true,
	// macOS
	"open": true, "pbcopy": true, "pbpaste": true,
	// Terminal
	"tmux": true, "screen": true,
	// Build tools (project-defined targets)
	"make": true, "cmake": true, "bazel": true,
	// Dev utilities
	"sleep": true, "seq": true,
	"pre-commit": true, "prettier": true, "eslint": true, "golangci-lint": true,
	"tsc": true, "jest": true, "pytest": true, "phpunit": true,
	// K8s tools
	"kustomize": true,
	// Version managers
	"asdf": true,
	// Team tools
	"access-gke": true,
}

func isAlwaysSafe(cmd string) bool {
	return alwaysSafeCommands[cmd]
}

var alwaysAskCommands = map[string]bool{
	"sudo":      true,
	"eval":      true,
	"dd":        true,
	"systemctl": true,
	"launchctl": true,
}

func isAlwaysAsk(cmd string) bool {
	return alwaysAskCommands[cmd]
}

// --- Special command handlers ---

func evaluateGit(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "git (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"status": true, "diff": true, "log": true, "show": true,
		"branch": true, "fetch": true, "stash": true, "add": true,
		"commit": true, "pull": true, "clone": true, "checkout": true,
		"rebase": true, "merge": true, "cherry-pick": true, "tag": true,
		"remote": true, "reflog": true, "rev-parse": true, "ls-files": true,
		"config": true, "init": true, "worktree": true, "bisect": true,
		"blame": true, "shortlog": true, "describe": true, "clean": true,
		"reset": true, "switch": true, "restore": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "git " + subCmd
	}

	if subCmd == "push" {
		return evaluateGitPush(args[1:])
	}

	return VerdictUncertain, "git " + subCmd
}

func evaluateGitPush(args []string) (Verdict, string) {
	isForce := false
	isDelete := false
	var positionalArgs []string

	for _, arg := range args {
		switch {
		case arg == "--force" || arg == "-f" || arg == "--force-with-lease":
			isForce = true
		case arg == "--delete" || arg == "-d":
			isDelete = true
		case strings.HasPrefix(arg, "-"):
			// other flags
		default:
			positionalArgs = append(positionalArgs, arg)
		}
	}

	// No force, no delete → always safe
	if !isForce && !isDelete {
		return VerdictAllow, "git push (no force)"
	}

	// Check if any positional arg refers to main/master
	for _, arg := range positionalArgs {
		lower := strings.ToLower(arg)
		if lower == "main" || lower == "master" ||
			strings.HasSuffix(lower, ":main") || strings.HasSuffix(lower, ":master") {
			if isForce {
				return VerdictAsk, "git push --force to " + arg
			}
			if isDelete {
				return VerdictAsk, "git push --delete " + arg
			}
		}
	}

	// Force/delete with explicit non-main branch
	if len(positionalArgs) >= 2 {
		return VerdictAllow, "git push to non-main branch"
	}

	// Force push without explicit branch → uncertain (could be on main)
	if isForce {
		return VerdictUncertain, "git push --force without explicit branch"
	}

	return VerdictUncertain, "git push --delete without explicit target"
}

func evaluateKubectl(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "kubectl (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"get": true, "describe": true, "logs": true, "top": true,
		"explain": true, "api-resources": true, "api-versions": true,
		"config": true, "cluster-info": true, "version": true,
		"auth": true, "port-forward": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "kubectl " + subCmd
	}

	if subCmd == "delete" {
		return evaluateKubectlDelete(args[1:])
	}

	writeSubcmds := map[string]bool{
		"apply": true, "create": true, "replace": true, "patch": true,
		"edit": true, "scale": true, "rollout": true, "exec": true,
		"cp": true, "run": true, "expose": true,
		"set": true, "label": true, "annotate": true, "taint": true,
		"cordon": true, "uncordon": true, "drain": true,
	}

	if writeSubcmds[subCmd] {
		return VerdictAsk, "kubectl " + subCmd
	}

	return VerdictUncertain, "kubectl " + subCmd
}

func evaluateKubectlDelete(args []string) (Verdict, string) {
	for _, arg := range args {
		if arg == "pod" || arg == "pods" || arg == "po" {
			return VerdictAllow, "kubectl delete pod"
		}
	}
	return VerdictAsk, "kubectl delete (non-pod resource)"
}

func evaluateRm(args []string, workDir string) (Verdict, string) {
	hasRecursive := false
	var targets []string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "r") || strings.Contains(arg, "R") {
				hasRecursive = true
			}
			continue
		}
		targets = append(targets, arg)
	}

	if len(targets) == 0 {
		return VerdictAllow, "rm with no targets"
	}

	for _, target := range targets {
		absTarget := target
		if !filepath.IsAbs(target) {
			absTarget = filepath.Join(workDir, target)
		}
		absTarget = filepath.Clean(absTarget)

		// Dangerous root paths
		home := os.Getenv("HOME")
		dangerousPaths := []string{"/", "/etc", "/usr", "/var", "/home", "/Users"}
		if home != "" {
			dangerousPaths = append(dangerousPaths, home)
		}
		for _, dp := range dangerousPaths {
			if absTarget == dp {
				return VerdictAsk, "rm targeting dangerous path: " + target
			}
		}

		// Parent traversal with recursive
		if hasRecursive && strings.Contains(target, "..") {
			return VerdictAsk, "rm -r with parent traversal: " + target
		}

		// Recursive rm outside project
		if hasRecursive && workDir != "" && !isWithinDir(absTarget, workDir) {
			return VerdictAsk, "rm -r outside project: " + target
		}
	}

	return VerdictAllow, "rm within project"
}

func evaluateChmod(args []string) (Verdict, string) {
	hasRecursive := false
	for _, arg := range args {
		if arg == "-R" || arg == "--recursive" {
			hasRecursive = true
		}
		if arg == "777" || arg == "a+rwx" {
			if hasRecursive {
				return VerdictAsk, "chmod -R 777"
			}
			return VerdictUncertain, "chmod 777"
		}
	}
	return VerdictAllow, "chmod"
}

func evaluateChown(args []string) (Verdict, string) {
	for _, arg := range args {
		if arg == "-R" || arg == "--recursive" {
			return VerdictUncertain, "chown -R"
		}
	}
	return VerdictAllow, "chown"
}

func evaluateGh(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictUncertain, "gh (no subcommand)"
	}

	switch args[0] {
	case "pr":
		return evaluateGhSub(args[0], args[1:], map[string]bool{
			"view": true, "list": true, "create": true, "checks": true,
			"diff": true, "ready": true, "comment": true, "checkout": true,
			"status": true,
		})
	case "issue":
		return evaluateGhSub(args[0], args[1:], map[string]bool{
			"view": true, "list": true, "create": true, "comment": true,
			"status": true,
		})
	case "run":
		return evaluateGhSub(args[0], args[1:], map[string]bool{
			"view": true, "list": true, "watch": true, "download": true,
		})
	case "repo":
		return evaluateGhRepo(args[1:])
	case "api", "auth":
		return VerdictAllow, "gh " + args[0]
	default:
		return VerdictUncertain, "gh " + args[0]
	}
}

func evaluateGhSub(parent string, args []string, safeCmds map[string]bool) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "gh " + parent
	}
	if safeCmds[args[0]] {
		return VerdictAllow, "gh " + parent + " " + args[0]
	}
	return VerdictUncertain, "gh " + parent + " " + args[0]
}

func evaluateGhRepo(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "gh repo"
	}
	safeCmds := map[string]bool{
		"view": true, "clone": true, "fork": true, "list": true,
	}
	if safeCmds[args[0]] {
		return VerdictAllow, "gh repo " + args[0]
	}
	if args[0] == "delete" {
		return VerdictAsk, "gh repo delete"
	}
	return VerdictUncertain, "gh repo " + args[0]
}

func evaluateGcloud(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictUncertain, "gcloud (no args)"
	}

	// Check for config subcommand
	if args[0] == "config" {
		if len(args) > 1 && (args[1] == "list" || args[1] == "get-value") {
			return VerdictAllow, "gcloud config read"
		}
		return VerdictUncertain, "gcloud config"
	}

	// Scan args for known safe/dangerous verbs
	for _, arg := range args {
		switch arg {
		case "list", "describe", "info", "get-iam-policy":
			return VerdictAllow, "gcloud read operation"
		case "create", "delete", "update", "deploy", "ssh", "set-iam-policy", "add-iam-policy-binding", "remove-iam-policy-binding":
			return VerdictAsk, "gcloud write operation: " + arg
		}
	}

	return VerdictUncertain, "gcloud command"
}

func evaluateBq(args []string) (Verdict, string) {
	for _, arg := range args {
		switch arg {
		case "ls", "show", "head":
			return VerdictAllow, "bq read operation"
		case "query":
			fullCmd := strings.ToUpper(strings.Join(args, " "))
			writeKeywords := []string{"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE"}
			for _, kw := range writeKeywords {
				if strings.Contains(fullCmd, kw) {
					return VerdictAsk, "bq write query: " + kw
				}
			}
			return VerdictAllow, "bq query (SELECT)"
		}
	}
	return VerdictUncertain, "bq command"
}

func evaluateAws(args []string) (Verdict, string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "describe-") || strings.HasPrefix(arg, "list-") || strings.HasPrefix(arg, "get-") {
			return VerdictAllow, "aws read operation"
		}
		if strings.HasPrefix(arg, "create-") || strings.HasPrefix(arg, "delete-") ||
			strings.HasPrefix(arg, "update-") || strings.HasPrefix(arg, "put-") ||
			strings.HasPrefix(arg, "run-") {
			return VerdictAsk, "aws write operation: " + arg
		}
	}
	return VerdictUncertain, "aws command"
}

func evaluateSed(args []string) (Verdict, string) {
	for _, arg := range args {
		if arg == "-i" || arg == "--in-place" || (strings.HasPrefix(arg, "-") && strings.Contains(arg, "i") && !strings.HasPrefix(arg, "--")) {
			return VerdictUncertain, "sed with in-place edit"
		}
	}
	return VerdictAllow, "sed (read-only)"
}

// --- File operation evaluation (Write/Edit/NotebookEdit) ---

func evaluateFileOp(toolName string, toolInput json.RawMessage, workDir string) (Verdict, string) {
	var input map[string]json.RawMessage
	if err := json.Unmarshal(toolInput, &input); err != nil {
		return VerdictUncertain, "failed to parse " + toolName + " input"
	}

	// Extract file path — Write/Edit use file_path, NotebookEdit uses notebook_path
	pathKey := "file_path"
	if toolName == "NotebookEdit" {
		pathKey = "notebook_path"
	}

	raw, ok := input[pathKey]
	if !ok {
		return VerdictUncertain, toolName + " missing " + pathKey
	}

	var filePath string
	if err := json.Unmarshal(raw, &filePath); err != nil {
		return VerdictUncertain, "failed to parse " + pathKey
	}

	filePath = filepath.Clean(filePath)

	if workDir != "" && isWithinDir(filePath, workDir) {
		return VerdictAllow, toolName + " within project"
	}

	if isSystemPath(filePath) {
		return VerdictAsk, toolName + " targeting system path: " + filePath
	}

	return VerdictUncertain, toolName + " outside project: " + filePath
}

func evaluateFileCmd(cmd string, args []string, workDir string) (Verdict, string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		absPath := arg
		if !filepath.IsAbs(arg) {
			absPath = filepath.Join(workDir, arg)
		}
		if isSystemPath(absPath) {
			return VerdictAsk, cmd + " targeting system path: " + arg
		}
	}
	return VerdictAllow, cmd + " (safe)"
}

// --- Path helpers ---

func isWithinDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// --- New command handlers ---

func evaluateSSH(args []string) (Verdict, string) {
	// Flags that consume the next argument
	flagsWithValue := map[string]bool{
		"-b": true, "-c": true, "-D": true, "-E": true, "-e": true,
		"-F": true, "-I": true, "-i": true, "-J": true, "-L": true,
		"-l": true, "-m": true, "-O": true, "-o": true, "-p": true,
		"-Q": true, "-R": true, "-S": true, "-W": true, "-w": true,
	}

	positionalCount := 0
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if flagsWithValue[arg] {
			skipNext = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		positionalCount++
		if positionalCount > 1 {
			return VerdictUncertain, "ssh with remote command"
		}
	}
	return VerdictAllow, "ssh (interactive)"
}

func evaluateDocker(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "docker (no subcommand)"
	}

	subCmd := args[0]

	// docker compose is equivalent to docker-compose
	if subCmd == "compose" {
		return evaluateDockerCompose(args[1:])
	}

	safeSubcmds := map[string]bool{
		"ps": true, "logs": true, "images": true, "inspect": true,
		"stats": true, "top": true, "history": true, "info": true,
		"version": true, "build": true, "pull": true, "tag": true,
		"login": true, "logout": true, "search": true,
		"events": true, "diff": true, "port": true, "wait": true,
		"cp": true, "create": true, "start": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "docker " + subCmd
	}

	return VerdictUncertain, "docker " + subCmd
}

func evaluateDockerCompose(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "docker-compose (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"up": true, "build": true, "pull": true, "start": true,
		"ps": true, "logs": true, "config": true, "images": true,
		"top": true, "version": true, "ls": true, "port": true,
		"create": true, "events": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "docker-compose " + subCmd
	}

	return VerdictUncertain, "docker-compose " + subCmd
}

func evaluateNodePkgMgr(cmd string, args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, cmd + " (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"install": true, "i": true, "ci": true, "add": true,
		"remove": true, "uninstall": true, "rm": true,
		"test": true, "t": true, "run": true, "start": true,
		"build": true, "dev": true, "lint": true, "format": true,
		"update": true, "upgrade": true, "outdated": true,
		"list": true, "ls": true, "info": true, "view": true,
		"init": true, "create": true, "exec": true,
		"audit": true, "cache": true, "config": true,
		"pack": true, "version": true, "why": true,
		"dedupe": true, "prune": true, "rebuild": true,
		"link": true, "unlink": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, cmd + " " + subCmd
	}

	if subCmd == "publish" {
		return VerdictAsk, cmd + " publish"
	}

	return VerdictUncertain, cmd + " " + subCmd
}

func evaluatePip(cmd string, args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, cmd + " (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"install": true, "uninstall": true,
		"list": true, "show": true, "freeze": true,
		"check": true, "config": true, "cache": true,
		"debug": true, "inspect": true, "download": true,
		"wheel": true, "hash": true, "search": true,
		"index": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, cmd + " " + subCmd
	}

	return VerdictUncertain, cmd + " " + subCmd
}

func evaluateRuntime(cmd string, args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, cmd + " (REPL)"
	}

	for _, arg := range args {
		switch arg {
		case "-c", "-e", "--eval":
			return VerdictUncertain, cmd + " with inline code"
		}
	}

	return VerdictAllow, cmd + " (script)"
}

func evaluateGo(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "go (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"build": true, "test": true, "vet": true, "fmt": true,
		"mod": true, "generate": true, "install": true, "get": true,
		"clean": true, "env": true, "version": true, "doc": true,
		"tool": true, "work": true, "run": true, "fix": true,
		"list": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "go " + subCmd
	}

	return VerdictUncertain, "go " + subCmd
}

func evaluateCargo(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "cargo (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"build": true, "test": true, "check": true, "clippy": true,
		"fmt": true, "doc": true, "clean": true, "update": true,
		"bench": true, "run": true, "new": true, "init": true,
		"add": true, "remove": true, "install": true, "search": true,
		"tree": true, "vendor": true, "fix": true, "fetch": true,
		"metadata": true, "verify-project": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "cargo " + subCmd
	}

	if subCmd == "publish" {
		return VerdictAsk, "cargo publish"
	}

	return VerdictUncertain, "cargo " + subCmd
}

func evaluateHelm(args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, "helm (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"list": true, "ls": true, "get": true, "status": true,
		"show": true, "template": true, "lint": true, "version": true,
		"repo": true, "search": true, "history": true, "env": true,
		"dependency": true, "plugin": true, "verify": true,
		"pull": true, "package": true, "create": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, "helm " + subCmd
	}

	askSubcmds := map[string]bool{
		"install": true, "upgrade": true, "uninstall": true,
		"delete": true, "rollback": true, "test": true,
	}

	if askSubcmds[subCmd] {
		return VerdictAsk, "helm " + subCmd
	}

	return VerdictUncertain, "helm " + subCmd
}

func evaluateFind(args []string) (Verdict, string) {
	for _, arg := range args {
		switch arg {
		case "-exec", "-execdir", "-delete", "-ok", "-okdir":
			return VerdictUncertain, "find with " + arg
		}
	}
	return VerdictAllow, "find (read-only)"
}

func evaluateTee(args []string, workDir string) (Verdict, string) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		absPath := arg
		if !filepath.IsAbs(arg) {
			absPath = filepath.Join(workDir, arg)
		}
		absPath = filepath.Clean(absPath)

		if isSystemPath(absPath) {
			return VerdictAsk, "tee to system path: " + arg
		}
		if workDir != "" && !isWithinDir(absPath, workDir) {
			return VerdictUncertain, "tee outside project: " + arg
		}
	}
	return VerdictAllow, "tee within project"
}

func evaluateTimeout(args []string, workDir string) (Verdict, string) {
	// Skip flags
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	// Skip duration argument
	if i < len(args) {
		i++
	}
	if i >= len(args) {
		return VerdictUncertain, "timeout (no command)"
	}
	return evaluateCommand(strings.Join(args[i:], " "), workDir)
}

func evaluatePackageManager(cmd string, args []string) (Verdict, string) {
	if len(args) == 0 {
		return VerdictAllow, cmd + " (no subcommand)"
	}

	subCmd := args[0]

	safeSubcmds := map[string]bool{
		"install": true, "add": true, "update": true,
		"upgrade": true, "search": true, "info": true,
		"show": true, "list": true, "outdated": true,
		"deps": true, "leaves": true, "uses": true,
		"doctor": true, "cleanup": true, "autoremove": true,
		"cache": true, "config": true, "tap": true,
		"untap": true,
	}

	if safeSubcmds[subCmd] {
		return VerdictAllow, cmd + " " + subCmd
	}

	return VerdictUncertain, cmd + " " + subCmd
}

func isSystemPath(path string) bool {
	path = filepath.Clean(path)

	systemPrefixes := []string{"/etc", "/usr", "/var", "/sys", "/proc", "/boot", "/sbin"}
	for _, prefix := range systemPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}

	home := os.Getenv("HOME")
	if home == "" {
		return false
	}

	// Sensitive dotfiles in home directory
	sensitivePaths := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".profile"),
	}
	for _, sp := range sensitivePaths {
		if path == sp {
			return true
		}
	}

	// Sensitive directories in home
	sensitiveDirs := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".aws"),
	}
	for _, sd := range sensitiveDirs {
		if path == sd || strings.HasPrefix(path, sd+"/") {
			return true
		}
	}

	return false
}
