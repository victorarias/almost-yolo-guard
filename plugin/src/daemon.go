package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DaemonConfig holds daemon configuration.
type DaemonConfig struct {
	IdleTimeout time.Duration
	SocketPath  string // override for testing; empty = default
	PIDPath     string // override for testing; empty = default
}

func (c DaemonConfig) socketPath() string {
	if c.SocketPath != "" {
		return c.SocketPath
	}
	return defaultSocketPath()
}

func (c DaemonConfig) pidPath() string {
	if c.PIDPath != "" {
		return c.PIDPath
	}
	return defaultPIDPath()
}

// Daemon is a persistent Unix socket server that evaluates tool calls via Claude.
type Daemon struct {
	evaluator    Evaluator
	config       DaemonConfig
	listener     net.Listener
	shuttingDown atomic.Bool
	wg           sync.WaitGroup
}

// NewDaemon creates a new daemon with the given evaluator and config.
func NewDaemon(evaluator Evaluator, config DaemonConfig) *Daemon {
	return &Daemon{
		evaluator: evaluator,
		config:    config,
	}
}

// Run starts the daemon, listens for connections, and blocks until shutdown.
func (d *Daemon) Run() error {
	socketPath := d.config.socketPath()
	pidPath := d.config.pidPath()

	// Ensure config directory exists
	os.MkdirAll(filepath.Dir(socketPath), 0755)

	// Check if daemon is already running
	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err == nil {
		conn.Close()
		return fmt.Errorf("daemon already running at %s", socketPath)
	}

	// Remove stale socket file
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	d.listener = listener

	// Write PID file
	os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Idle timer
	idleTimeout := d.config.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}
	idleTimer := time.NewTimer(idleTimeout)

	// Shutdown channel
	done := make(chan struct{})

	// Accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if d.shuttingDown.Load() {
					return
				}
				continue
			}
			idleTimer.Reset(idleTimeout)
			d.wg.Add(1)
			// Handle sequentially (one request at a time, matching Claude Code's behavior)
			d.handleConnection(conn)
			d.wg.Done()
		}
	}()

	// Wait for shutdown signal or idle timeout
	go func() {
		select {
		case <-sigCh:
		case <-idleTimer.C:
		}
		close(done)
	}()

	<-done
	d.Shutdown()
	return nil
}

func (d *Daemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set deadline for the entire request/response cycle
	conn.SetDeadline(time.Now().Add(35 * time.Second))

	var req EvalRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		resp := EvalResponse{Decision: "ASK", Reason: "failed to decode request: " + err.Error()}
		json.NewEncoder(conn).Encode(resp)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := d.evaluator.Evaluate(ctx, req)
	if err != nil {
		resp = EvalResponse{Decision: "ASK", Reason: "evaluator error: " + err.Error()}
	}

	json.NewEncoder(conn).Encode(resp)
}

// Shutdown gracefully stops the daemon.
func (d *Daemon) Shutdown() {
	if !d.shuttingDown.CompareAndSwap(false, true) {
		return // already shutting down
	}

	if d.listener != nil {
		d.listener.Close()
	}

	d.wg.Wait()

	os.Remove(d.config.socketPath())
	os.Remove(d.config.pidPath())

	d.evaluator.Close()
}

// --- Path helpers ---

func configDir() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "almost-yolo-guard")
}

func defaultSocketPath() string {
	return filepath.Join(configDir(), "daemon.sock")
}

func defaultPIDPath() string {
	return filepath.Join(configDir(), "daemon.pid")
}

// --- Daemon control commands ---

func daemonStatus() {
	pidPath := defaultPIDPath()
	socketPath := defaultSocketPath()

	pid, err := readPIDFile(pidPath)
	if err != nil {
		fmt.Println("not running")
		os.Exit(1)
	}

	if !processAlive(pid) {
		fmt.Printf("not running (stale PID %d)\n", pid)
		os.Remove(pidPath)
		os.Remove(socketPath)
		os.Exit(1)
	}

	conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
	if err != nil {
		fmt.Printf("process %d alive but socket not responding\n", pid)
		os.Exit(1)
	}
	conn.Close()

	fmt.Printf("running (PID %d)\n", pid)
}

func daemonStop() {
	pidPath := defaultPIDPath()
	socketPath := defaultSocketPath()

	pid, err := readPIDFile(pidPath)
	if err != nil {
		fmt.Println("not running")
		return
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("process %d not found, cleaning up\n", pid)
		os.Remove(pidPath)
		os.Remove(socketPath)
		return
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Printf("could not signal %d: %v, cleaning up\n", pid, err)
		os.Remove(pidPath)
		os.Remove(socketPath)
		return
	}

	// Wait for socket to disappear
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			fmt.Printf("stopped (PID %d)\n", pid)
			return
		}
	}

	fmt.Printf("sent SIGTERM to %d but socket still exists\n", pid)
}

func daemonRestart() {
	daemonStop()
	time.Sleep(200 * time.Millisecond)

	if err := startDaemonProcess(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start: %v\n", err)
		os.Exit(1)
	}

	socketPath := defaultSocketPath()
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			fmt.Println("restarted")
			return
		}
	}

	fmt.Println("started but not yet accepting connections")
}

func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// runDaemon is the top-level entry point for `almost-yolo-guard daemon`.
func runDaemon() {
	model := getModel()
	evaluator := NewClaudeEvaluator(model)

	config := DaemonConfig{
		IdleTimeout: 5 * time.Minute,
	}

	d := NewDaemon(evaluator, config)
	if err := d.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		os.Exit(1)
	}
}
