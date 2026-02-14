package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockEvaluator returns a fixed response for testing.
type mockEvaluator struct {
	response EvalResponse
	err      error
	called   int
}

func (m *mockEvaluator) Evaluate(ctx context.Context, req EvalRequest) (EvalResponse, error) {
	m.called++
	return m.response, m.err
}

func (m *mockEvaluator) Close() error { return nil }

func TestDaemonAcceptsConnection(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	pidPath := filepath.Join(tmpDir, "test.pid")

	mock := &mockEvaluator{response: EvalResponse{Decision: "ALLOW", Reason: "test safe"}}

	d := NewDaemon(mock, DaemonConfig{
		IdleTimeout: 5 * time.Second,
		SocketPath:  socketPath,
		PIDPath:     pidPath,
	})

	// Start daemon in background
	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	// Wait for socket to be ready
	waitForSocket(t, socketPath, 2*time.Second)

	// Connect and send request
	resp := sendTestRequest(t, socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"ls"}`,
		WorkDir:   "/proj",
	})

	if resp.Decision != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", resp.Decision)
	}
	if resp.Reason != "test safe" {
		t.Errorf("expected reason 'test safe', got %q", resp.Reason)
	}
	if mock.called != 1 {
		t.Errorf("expected evaluator called once, got %d", mock.called)
	}

	d.Shutdown()
}

func TestDaemonMultipleRequests(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	pidPath := filepath.Join(tmpDir, "test.pid")

	mock := &mockEvaluator{response: EvalResponse{Decision: "ASK", Reason: "dangerous"}}

	d := NewDaemon(mock, DaemonConfig{
		IdleTimeout: 5 * time.Second,
		SocketPath:  socketPath,
		PIDPath:     pidPath,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	waitForSocket(t, socketPath, 2*time.Second)

	// Send multiple sequential requests
	for i := 0; i < 3; i++ {
		resp := sendTestRequest(t, socketPath, EvalRequest{
			ToolName:  "Bash",
			ToolInput: `{"command":"kubectl apply -f deploy.yaml"}`,
			WorkDir:   "/proj",
		})
		if resp.Decision != "ASK" {
			t.Errorf("request %d: expected ASK, got %s", i, resp.Decision)
		}
	}

	if mock.called != 3 {
		t.Errorf("expected evaluator called 3 times, got %d", mock.called)
	}

	d.Shutdown()
}

func TestDaemonIdleShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	pidPath := filepath.Join(tmpDir, "test.pid")

	mock := &mockEvaluator{response: EvalResponse{Decision: "ALLOW", Reason: "safe"}}

	d := NewDaemon(mock, DaemonConfig{
		IdleTimeout: 500 * time.Millisecond, // very short for testing
		SocketPath:  socketPath,
		PIDPath:     pidPath,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	waitForSocket(t, socketPath, 2*time.Second)

	// Wait for idle timeout
	time.Sleep(1 * time.Second)

	// Should no longer accept connections
	_, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err == nil {
		t.Error("expected connection refused after idle shutdown")
	}
}

func TestDaemonEvaluatorError(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	pidPath := filepath.Join(tmpDir, "test.pid")

	mock := &mockEvaluator{
		response: EvalResponse{},
		err:      context.DeadlineExceeded,
	}

	d := NewDaemon(mock, DaemonConfig{
		IdleTimeout: 5 * time.Second,
		SocketPath:  socketPath,
		PIDPath:     pidPath,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	waitForSocket(t, socketPath, 2*time.Second)

	resp := sendTestRequest(t, socketPath, EvalRequest{
		ToolName:  "Bash",
		ToolInput: `{"command":"complex-thing"}`,
		WorkDir:   "/proj",
	})

	// Should fail-safe to ASK
	if resp.Decision != "ASK" {
		t.Errorf("expected ASK on evaluator error, got %s", resp.Decision)
	}

	d.Shutdown()
}

func TestDaemonCleanupOnShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	pidPath := filepath.Join(tmpDir, "test.pid")

	mock := &mockEvaluator{response: EvalResponse{Decision: "ALLOW", Reason: "safe"}}

	d := NewDaemon(mock, DaemonConfig{
		IdleTimeout: 5 * time.Second,
		SocketPath:  socketPath,
		PIDPath:     pidPath,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- d.Run() }()

	waitForSocket(t, socketPath, 2*time.Second)

	d.Shutdown()

	// Socket and PID files should be cleaned up
	if fileExists(socketPath) {
		t.Error("socket file should be removed after shutdown")
	}
	if fileExists(pidPath) {
		t.Error("PID file should be removed after shutdown")
	}
}

// --- Test helpers ---

func waitForSocket(t *testing.T, socketPath string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s not ready after %s", socketPath, timeout)
}

func sendTestRequest(t *testing.T, socketPath string, req EvalRequest) EvalResponse {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to daemon: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	var resp EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	return resp
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
