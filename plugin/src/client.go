package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// runClient is the main hook client entry point.
func runClient() {
	hookInput, err := readHookInput()
	if err != nil {
		exitPassthrough("failed to read input: " + err.Error())
		return
	}

	if hookInput.ToolName == "" {
		exitPassthrough("")
		return
	}

	// Skip evaluation for tools that don't need security review
	if shouldSkipEvaluation(hookInput.ToolName) {
		exitPassthrough("")
		return
	}

	toolInputStr := string(hookInput.ToolInput)

	// Step 1: Try rule engine (instant, ~90% of cases)
	verdict, reason := EvaluateRules(hookInput.ToolName, hookInput.ToolInput, hookInput.WorkingDir)
	switch verdict {
	case VerdictAllow:
		logDecision(hookInput.ToolName, toolInputStr, hookInput.WorkingDir, "ALLOW", "rules", reason)
		writeAllowOutput()
		return
	case VerdictAsk:
		logDecision(hookInput.ToolName, toolInputStr, hookInput.WorkingDir, "ASK", "rules", reason)
		exitPassthrough("")
		return
	}

	// Step 2: VerdictUncertain — try daemon
	resp, err := queryDaemon(hookInput.ToolName, toolInputStr, hookInput.WorkingDir)
	if err != nil {
		// Step 3: Daemon unavailable — fail-safe to ASK
		logDecision(hookInput.ToolName, toolInputStr, hookInput.WorkingDir, "ASK", "fail-safe", err.Error())
		exitPassthrough("")
		return
	}

	logDecision(hookInput.ToolName, toolInputStr, hookInput.WorkingDir, resp.Decision, "daemon", resp.Reason)

	if resp.Decision == "ALLOW" {
		writeAllowOutput()
	} else {
		exitPassthrough("")
	}
}

// queryDaemon connects to the daemon, auto-starting it if needed.
func queryDaemon(toolName, toolInput, workDir string) (*EvalResponse, error) {
	socketPath := defaultSocketPath()

	// Try connecting to existing daemon
	resp, err := sendDaemonRequest(socketPath, EvalRequest{
		ToolName:  toolName,
		ToolInput: toolInput,
		WorkDir:   workDir,
	})
	if err == nil {
		return resp, nil
	}

	// Connection failed — try starting daemon
	if startErr := startDaemonProcess(); startErr != nil {
		return nil, fmt.Errorf("failed to start daemon: %w", startErr)
	}

	// Retry with backoff (wait up to 2s for daemon to start)
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		resp, err = sendDaemonRequest(socketPath, EvalRequest{
			ToolName:  toolName,
			ToolInput: toolInput,
			WorkDir:   workDir,
		})
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("daemon not available after retries: %w", err)
}

// sendDaemonRequest sends a single request to the daemon and reads the response.
func sendDaemonRequest(socketPath string, req EvalRequest) (*EvalResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Slightly more than Claude's 30s timeout
	conn.SetDeadline(time.Now().Add(35 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	var resp EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &resp, nil
}

// startDaemonProcess starts the daemon as a background process.
func startDaemonProcess() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exePath, "daemon")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	return cmd.Start()
}
