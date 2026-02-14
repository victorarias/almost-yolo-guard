package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func logDecision(toolName, toolInput, workDir, decision, source, reason string) {
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
	logEntry := fmt.Sprintf("[%s] %s | tool=%s | dir=%s | source=%s | input=%s | reason=%s\n",
		timestamp, decision, toolName, workDir, source, toolInput, reason)
	f.WriteString(logEntry)
}
