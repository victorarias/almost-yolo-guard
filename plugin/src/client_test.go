package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSendDaemonRequest(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a fake daemon
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create test socket: %v", err)
	}
	defer listener.Close()

	// Serve one request
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req EvalRequest
		json.NewDecoder(conn).Decode(&req)

		resp := EvalResponse{Decision: "ALLOW", Reason: "mock says safe"}
		json.NewEncoder(conn).Encode(resp)
	}()

	// Client sends request
	resp, err := sendDaemonRequest(socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"ls"}`,
		WorkDir:   "/proj",
	})
	if err != nil {
		t.Fatalf("sendDaemonRequest failed: %v", err)
	}

	if resp.Decision != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", resp.Decision)
	}
	if resp.Reason != "mock says safe" {
		t.Errorf("expected 'mock says safe', got %q", resp.Reason)
	}
}

func TestSendDaemonRequestNoSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	_, err := sendDaemonRequest(socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"ls"}`,
		WorkDir:   "/proj",
	})
	if err == nil {
		t.Error("expected error when no daemon is running")
	}
}

func TestSendDaemonRequestBadResponse(t *testing.T) {
	// Use short path to stay within macOS 104-char Unix socket limit
	tmpDir, err := os.MkdirTemp("", "yt-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	socketPath := filepath.Join(tmpDir, "t.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create test socket: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte("not json\n"))
	}()

	_, err = sendDaemonRequest(socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"ls"}`,
		WorkDir:   "/proj",
	})
	if err == nil {
		t.Error("expected error for bad response")
	}
}

func TestClientFallsBackToAsk(t *testing.T) {
	// When daemon is unavailable and rule engine returns uncertain,
	// the client should fall back to ASK.
	// This is tested through the integration tests (binary E2E).
	// Here we verify the individual components.

	socketPath := filepath.Join(t.TempDir(), "nonexistent.sock")

	_, err := sendDaemonRequest(socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"unknowncmd --flag"}`,
		WorkDir:   "/proj",
	})

	// Should fail since no daemon
	if err == nil {
		t.Error("expected error when daemon unavailable")
	}
}
