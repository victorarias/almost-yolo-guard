# almost-yolo-guard

A Claude Code plugin that routes permission requests to Opus 4.5 for intelligent auto-approval.

Inspired by [this tweet](https://x.com/victorarias/status/1885508850920591752) about using Claude Opus as a security reviewer for Claude Code.

## What It Does

When Claude Code wants to run a potentially risky operation (shell command, file write, etc.), it shows you a permission dialog. This plugin intercepts those requests and asks Opus 4.5 to evaluate whether the operation is safe.

- **Safe operations** (reads, builds, tests, git on feature branches) → **auto-approved**
- **Risky operations** (cloud mutations, writes to system paths, git force-push to main) → **falls through to normal dialog**

This gives you an "almost YOLO" mode — most routine operations sail through, but dangerous ones still require your explicit approval.

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- Go 1.21+ (for building from source)
- Access to Claude Opus 4.5 through your Claude CLI

## Installation

### Via Claude Code Plugin (Recommended)

```bash
# Add the repository as a marketplace
/plugin marketplace add victorarias/almost-yolo-guard

# Install the plugin
/plugin install almost-yolo-guard@almost-yolo-guard
```

That's it! The plugin auto-configures the PermissionRequest hook.

### Manual Installation (Development)

```bash
git clone https://github.com/victorarias/almost-yolo-guard
cd almost-yolo-guard/src
go build -o ../bin/almost-yolo-guard

# Use as local plugin during development
claude --plugin-dir ~/path/to/almost-yolo-guard
```

## How It Works

1. Claude Code needs to run a tool that would show a permission dialog
2. The PermissionRequest hook intercepts the request
3. The tool name, input, and working directory are sent to Opus 4.5
4. Opus evaluates against safety rules and responds ALLOW or ASK
5. **ALLOW** → tool runs immediately without dialog
6. **ASK** → normal permission dialog appears

## Safety Rules

### Auto-approved (ALLOW)

**Read operations:**
- File inspection (`cat`, `head`, `grep`, `find`, etc.)
- System info (`whoami`, `uname`, `ps`, etc.)
- Network inspection (`ping`, `dig`, `curl` GET)

**Development:**
- Build/run (`go`, `npm`, `cargo`, `make`, etc.)
- Tests (`go test`, `npm test`, etc.)
- Git operations on feature branches (including `--force`, `reset --hard`)
- Docker (`build`, `run`, `ps`, `logs`)

**Cloud CLI reads:**
- `kubectl get`, `describe`, `logs`
- `kubectl delete pod` (pods are ephemeral)
- `gcloud list`, `describe`
- `bq query` (SELECT only)

**File writes:**
- Write/Edit within project directories
- Build artifacts, temp files

### Require approval (ASK)

**Destructive cloud operations:**
- `kubectl apply`, `delete` (non-pods), `exec`
- `gcloud create`, `delete`, `deploy`
- `bq` with INSERT, UPDATE, DELETE

**Git to main/master:**
- `git push --force` to main/master
- `git push --delete` main/master

**Dangerous file operations:**
- `rm -rf` targeting `~`, `/`, system paths
- Write/Edit to `/etc`, `~/.bashrc`, etc.

**Other:**
- `sudo` anything
- `curl | bash` (pipe to shell)
- `gh repo delete`

## Configuration

### Custom Model

Set `ALMOST_YOLO_MODEL` to use a different Claude model:

```bash
export ALMOST_YOLO_MODEL=claude-sonnet-4-20250514
```

Default: `claude-opus-4-5-20251101`

### Decision Log

All decisions are logged to `~/.config/almost-yolo-guard/decisions.log`:

```bash
tail -f ~/.config/almost-yolo-guard/decisions.log
```

Example log entry:
```
[2025-01-15 14:30:22] ALLOW | tool=Bash | dir=/Users/me/project | input={"command":"go test ./..."} | reason=ALLOW
[2025-01-15 14:31:05] ASK | tool=Bash | dir=/Users/me/project | input={"command":"kubectl apply -f deploy.yaml"} | reason=ASK
```

## Customizing Safety Rules

The safety rules are embedded in the system prompt in `src/main.go`. To customize:

1. Fork this repo
2. Edit the `systemPrompt` constant in `src/main.go`
3. Rebuild: `cd src && go build -o ../bin/almost-yolo-guard`
4. Use your local copy: `claude --plugin-dir ~/path/to/almost-yolo-guard`

## Troubleshooting

### Hook not running

Check that the plugin is installed:
```bash
/plugin list
```

### Unexpected decisions

Check the log:
```bash
cat ~/.config/almost-yolo-guard/decisions.log
```

### Timeout errors

The plugin has a 30-second timeout for Opus evaluation. If you're seeing timeouts, check your Claude CLI configuration and network connection.

## License

MIT
