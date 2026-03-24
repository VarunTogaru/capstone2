# Privileged Helper Contract and Packaging Plan

## Goal

Provide user-friendly elevated scans without running the main app as root/admin.

## Architecture

- `nmap-insight-app` (unprivileged): UI + scan orchestration.
- `nmap-insight-helper` (privileged service): executes approved elevated Nmap scans only.
- IPC is local-only:
  - macOS/Linux: Unix domain socket
  - Windows: named pipe

## Security Model

- Helper never executes shell commands.
- Helper only launches `nmap` via argument arrays.
- Helper enforces a strict allowlist of elevated flags.
- Helper rejects unknown flags, malformed targets, or unsafe combos.
- Helper logs privileged requests with timestamp, user id, and final arg list.

## Allowed Elevated Operations (v1)

- Scan types: `-sS`, `-sU`, `-O`, `-A`, `--traceroute`
- Safe utility flags: `-p`, `-Pn`, `-n`, `-T0..-T5`, `--top-ports`, `--open`, `--reason`
- Optional NSE categories only: `--script=default,safe,vuln`
- Blocked in elevated mode (v1): spoofing/evasion/raw packet crafting flags and file output flags.

## IPC Contract (v1)

### `GET /health`

- Purpose: verify helper is installed and reachable.
- Response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "platform": "darwin"
}
```

### `POST /validate`

- Purpose: dry-run validation before privileged execution.
- Request:
```json
{
  "target": "scanme.nmap.org",
  "scan_type": "syn",
  "ports": "22,80,443",
  "extra_args": ["-Pn", "-T4", "--open"]
}
```
- Response:
```json
{
  "allowed": true,
  "errors": [],
  "command": ["nmap", "-sS", "-p", "22,80,443", "-Pn", "-T4", "--open", "-oX", "-", "scanme.nmap.org"]
}
```

### `POST /scan`

- Purpose: run one privileged scan.
- Request:
```json
{
  "request_id": "req_123",
  "target": "scanme.nmap.org",
  "scan_type": "syn",
  "ports": "22,80,443",
  "extra_args": ["-Pn", "-T4", "--open"],
  "timeout_seconds": 180
}
```
- Response:
```json
{
  "request_id": "req_123",
  "status": "completed",
  "command": ["nmap", "-sS", "-p", "22,80,443", "-Pn", "-T4", "--open", "-oX", "-", "scanme.nmap.org"],
  "xml": "<nmaprun>...</nmaprun>",
  "stderr": ""
}
```

### `POST /cancel`

- Purpose: stop running privileged scan by request id.
- Request:
```json
{
  "request_id": "req_123"
}
```
- Response:
```json
{
  "request_id": "req_123",
  "status": "canceled"
}
```

## App Integration Flow

1. User checks “Advanced scan”.
2. App calls helper `/health`.
3. App calls `/validate`.
4. If valid, app calls `/scan`.
5. App parses XML and renders normal result UI.

## Error UX Contract

- `HELPER_NOT_AVAILABLE`: helper not installed/running.
- `HELPER_PERMISSION_DENIED`: helper installed but not permitted.
- `ELEVATED_FLAG_NOT_ALLOWED`: blocked flag in elevated mode.
- `INVALID_REQUEST`: missing/invalid target, ports, or options.
- `SCAN_TIMEOUT`: privileged scan exceeded timeout.
- `SCAN_RUNTIME_ERROR`: Nmap returned non-zero with stderr.

## Packaging Strategy

## Phase 1 (macOS first)

- Main app packaged as desktop app (Tauri or Python app bundle).
- Helper installed as `launchd` daemon:
  - Label: `com.nmapinsight.helper`
  - Runs as root
  - Socket file with strict permissions
- Installer type: signed `.pkg`.
- Installer performs:
  - install app binary
  - install helper binary + plist
  - load helper service
  - verify helper health check

## Phase 2 (Windows/Linux)

- Windows helper as signed Windows Service + named pipe ACL.
- Linux helper as `systemd` service + Unix socket permissions.

## Release Requirements

- Code signing for app + helper binaries.
- Notarization on macOS.
- Auto-update channel for app and helper version compatibility.
- Semver compatibility rule:
  - app and helper major versions must match.

## Immediate Implementation Order

1. Add internal interface in app for privileged scan provider.
2. Build helper validator/allowlist module.
3. Implement helper `/health`, `/validate`, `/scan`, `/cancel`.
4. Add UI toggle for normal vs advanced scan mode.
5. Add integration tests for allowlist and privilege path.
