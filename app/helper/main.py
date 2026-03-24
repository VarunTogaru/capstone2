import asyncio
import hmac
import os
import platform
import secrets
import shutil
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.connect.privileged_allowlist import validate_privileged_command
from app.connect.runner import build_nmap_args
from app.scan.request import Request

TOKEN_ENV = "NMAP_HELPER_TOKEN"
TOKEN_FILE_ENV = "NMAP_HELPER_TOKEN_FILE"
DEFAULT_TOKEN_FILE = Path("/var/run/nmap-insight/helper.token")


def _init_auth_token() -> str:
    """Load or generate the shared authentication token."""
    token = os.getenv(TOKEN_ENV)
    if token:
        return token

    token_file = Path(os.getenv(TOKEN_FILE_ENV, str(DEFAULT_TOKEN_FILE)))
    if token_file.exists():
        stored = token_file.read_text().strip()
        if stored:
            return stored

    token = secrets.token_urlsafe(32)
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(token)
    token_file.chmod(0o600)
    return token


AUTH_TOKEN: str = _init_auth_token()

app = FastAPI(title="Nmap Insight Privileged Helper")

RUNNING_PROCESSES: dict[str, asyncio.subprocess.Process] = {}
CANCELED_REQUESTS: set[str] = set()


class CancelRequest(BaseModel):
    request_id: str


async def _require_auth(authorization: str = Header(...)) -> None:
    """Validate Bearer token on protected endpoints."""
    scheme, _, credentials = authorization.partition(" ")
    if scheme.lower() != "bearer" or not credentials:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if not hmac.compare_digest(credentials, AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid bearer token")


def _command_for_request(req: Request) -> tuple[list[str], list[str]]:
    command = build_nmap_args(req)
    errors = validate_privileged_command(command)
    return command, errors


@app.get("/health")
async def health() -> dict:
    token_file = Path(os.getenv(TOKEN_FILE_ENV, str(DEFAULT_TOKEN_FILE)))
    return {
        "status": "ok",
        "version": "1.0.0",
        "platform": platform.system().lower(),
        "token_file": str(token_file),
    }


@app.post("/validate", dependencies=[Depends(_require_auth)])
async def validate(req: Request) -> dict:
    command, errors = _command_for_request(req)
    return {
        "allowed": len(errors) == 0,
        "errors": errors,
        "command": command,
    }


@app.post("/scan", dependencies=[Depends(_require_auth)])
async def scan(req: Request) -> dict:
    if shutil.which("nmap") is None:
        raise HTTPException(status_code=500, detail="SCAN_RUNTIME_ERROR: nmap not found in PATH")

    command, errors = _command_for_request(req)
    if errors:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "ELEVATED_FLAG_NOT_ALLOWED",
                "errors": errors,
            },
        )

    request_id = req.request_id or f"req_{uuid.uuid4().hex[:12]}"
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    RUNNING_PROCESSES[request_id] = process

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=req.timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise HTTPException(
            status_code=408,
            detail="SCAN_TIMEOUT: privileged scan exceeded timeout",
        ) from exc
    finally:
        RUNNING_PROCESSES.pop(request_id, None)

    stderr_text = stderr.decode(errors="ignore")

    if request_id in CANCELED_REQUESTS:
        CANCELED_REQUESTS.discard(request_id)
        return {
            "request_id": request_id,
            "status": "canceled",
            "command": command,
            "xml": "",
            "stderr": stderr_text,
        }

    if process.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SCAN_RUNTIME_ERROR",
                "stderr": stderr_text or "Nmap failed",
            },
        )

    return {
        "request_id": request_id,
        "status": "completed",
        "command": command,
        "xml": stdout.decode(errors="ignore"),
        "stderr": stderr_text,
    }


@app.post("/cancel", dependencies=[Depends(_require_auth)])
async def cancel(payload: CancelRequest) -> dict:
    process = RUNNING_PROCESSES.get(payload.request_id)
    if process is None:
        raise HTTPException(status_code=404, detail="Request ID not found")

    CANCELED_REQUESTS.add(payload.request_id)
    if process.returncode is None:
        process.kill()

    return {
        "request_id": payload.request_id,
        "status": "canceled",
    }