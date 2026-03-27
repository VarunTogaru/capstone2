import asyncio
import logging
import shutil
from typing import Optional
from app.scan.request import Request

logger = logging.getLogger("nmap_insight.runner")

SCAN_TYPE_FLAGS = {
    "tcp": ["-sT"],
    "syn": ["-sS"],
    "version": ["-sV"],
    "custom": [],
}

# In-memory tracking of running scan processes for cancellation.
RUNNING_PROCESSES: dict[str, asyncio.subprocess.Process] = {}


def build_nmap_args(req: Request) -> list[str]:
    if req.scan_type not in SCAN_TYPE_FLAGS:
        raise RuntimeError("Unsupported scan type")

    args = ["nmap", *SCAN_TYPE_FLAGS[req.scan_type]]
    if req.ports:
        args += ["-p", req.ports]
    if req.extra_args:
        args += req.extra_args

    # Force XML output to stdout so the parser can consume it.
    args += ["-oX", "-", req.target]
    return args


def cancel_scan(request_id: str) -> bool:
    """Cancel a running scan by request_id. Returns True if found and killed."""
    proc = RUNNING_PROCESSES.pop(request_id, None)
    if proc is None:
        return False
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    logger.info("Scan canceled: request_id=%s", request_id)
    return True


async def run_nmap_xml(req: Request) -> str:
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap is not installed or not in PATH")

    request_id = req.request_id or ""
    args = build_nmap_args(req)
    logger.info("Running nmap: %s", " ".join(args))

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    if request_id:
        RUNNING_PROCESSES[request_id] = proc

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=req.timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.communicate()
        logger.warning("Nmap scan timed out after %ds", req.timeout_seconds)
        raise RuntimeError("SCAN_TIMEOUT: scan exceeded timeout") from exc
    finally:
        RUNNING_PROCESSES.pop(request_id, None)

    if proc.returncode != 0:
        stderr_text = stderr.decode(errors="ignore")
        logger.error("Nmap failed (rc=%d): %s", proc.returncode, stderr_text)
        # Killed processes (cancel) return -9; treat as cancellation.
        if proc.returncode < 0:
            raise RuntimeError("SCAN_CANCELED: scan was canceled")
        raise RuntimeError(stderr_text or "Nmap failed")

    return stdout.decode(errors="ignore")
