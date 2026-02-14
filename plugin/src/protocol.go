package main

// Verdict represents the outcome of a rule engine evaluation.
type Verdict int

const (
	VerdictAllow     Verdict = iota // Deterministically safe
	VerdictAsk                      // Deterministically requires user approval
	VerdictUncertain                // Cannot determine — needs Claude evaluation
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "ALLOW"
	case VerdictAsk:
		return "ASK"
	default:
		return "UNCERTAIN"
	}
}

// EvalRequest is sent from client to daemon via Unix socket.
type EvalRequest struct {
	ToolName  string `json:"tool_name"`
	ToolInput string `json:"tool_input"`
	WorkDir   string `json:"work_dir"`
}

// EvalResponse is sent from daemon to client via Unix socket.
type EvalResponse struct {
	Decision string `json:"decision"` // "ALLOW" or "ASK"
	Reason   string `json:"reason"`
}
