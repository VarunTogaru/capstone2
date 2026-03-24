# Nmap Insight

Nmap Insight is a local-first web application for building and running Nmap
scans with a guided UI and structured results output.

## Current Status

- FastAPI app with `/scan` endpoint
- Local web UI served from app (`/`)
- Standard scan mode (non-privileged)
- Advanced scan mode through a privileged helper path
- XML parsing into structured JSON results

## Project Goals

- Reduce CLI complexity for scan construction
- Improve result readability with structured output
- Keep scanning local to the user machine
- Support a path to commercial distribution later

## Tech Stack

- Python 3.10+
- FastAPI
- Pydantic
- Uvicorn
- Nmap (installed on host machine)

## Repository Layout

- `app/main.py`: main FastAPI app and UI entry route
- `app/router.py`: scan API route
- `app/scan/request.py`: request model
- `app/connect/runner.py`: standard local scan execution
- `app/connect/dispatcher.py`: privileged vs standard scan dispatch
- `app/connect/helper_client.py`: client to privileged helper service
- `app/connect/privileged_allowlist.py`: elevated flag controls
- `app/helper/main.py`: privileged helper API
- `app/connect/parser.py`: XML to JSON parser
- `app/static/index.html`: frontend UI
- `docs/privileged-helper-contract.md`: helper architecture and packaging plan

## Quick Start (Local Dev)

1. Create and activate a Python virtual environment.
2. Install dependencies:
   - `pip install -r app/requirements.txt`
3. Ensure Nmap is installed and available in `PATH`.
4. Start main app:
   - `uvicorn app.main:app --reload`
5. Open:
   - `http://127.0.0.1:8000`

## Advanced Mode (Privileged Helper)

Advanced mode is optional and intended for scans that may require elevated
privileges.

1. Start helper service (development example):
   - `sudo uvicorn app.helper.main:app --host 127.0.0.1 --port 8765`
2. Start main app normally:
   - `uvicorn app.main:app --reload`
3. In UI, enable:
   - `Advanced` checkbox

Note: The production plan is to run the helper as an installed system service
instead of manually launching with `sudo`.

## API (Current)

### `POST /scan`

Request body fields:

- `target` (string, required)
- `scan_type` (string: `tcp|syn|version|custom`)
- `ports` (string or null)
- `extra_args` (array of strings)
- `use_privileged` (boolean)
- `timeout_seconds` (int, 10 to 3600)
- `request_id` (string or null)

Response:

- Parsed JSON:
  - `hosts[]`
    - `address`
    - `ports[]`
      - `port`
      - `proto`
      - `state`
      - `service`

## Security Notes

- Scans are executed with argument arrays, not shell strings.
- Advanced mode uses allowlist validation for elevated flags.
- Keep this service bound to loopback unless auth and hardening are added.
- Do not scan networks/systems without authorization.

## Performance Notes

- Scan runtime is mostly dominated by Nmap behavior and selected flags.
- `timeout_seconds` is supported to prevent runaway scans.
- Faster presets should prefer `-n`, `--open`, and smaller port sets.

## Packaging Direction

Target user-friendly packaging flow:

- Desktop installer for end users
- Main app service (unprivileged)
- Privileged helper service (installed once)
- Signed binaries and installer
- Auto-update support

See `docs/privileged-helper-contract.md` for implementation direction.

## Packaging and Installation

### Prerequisites for Building

1.  **Python 3.10+** and a virtual environment.
2.  **Inno Setup** (for creating the Windows installer): [Download Inno Setup](https://jrsoftware.org/isdl.php)

### Building the Executable

The project uses `PyInstaller` to bundle the FastAPI app into a single executable.

1.  Install the build dependencies:
    ```powershell
    pip install -r app/requirements.txt
    ```
2.  Run PyInstaller using the provided `.spec` file:
    ```powershell
    pyinstaller main.spec
    ```
    This will generate a `dist/main.exe` file.

### Creating the Installer

The installer is built using Inno Setup to provide a standard Windows installation experience.

1.  Open `installer.iss` in the **Inno Setup Compiler**.
2.  Click **Build** -> **Compile** (or press `Ctrl+F9`).
3.  The final installer `NMAP_Insight_Setup.exe` will be created in the `dist/` directory.

### Installation

1.  Locate `NMAP_Insight_Setup.exe` in the `dist/` folder.
2.  Run the installer (requires **Administrator privileges** to install to `Program Files`).
3.  Follow the setup wizard to complete the installation.
4.  Launch **Nmap Insight** from the Desktop shortcut or Start Menu.

## Ownership and License

This project is proprietary and owned by Caleb Tunks.

See the [LICENSE](LICENSE) file for full terms.
