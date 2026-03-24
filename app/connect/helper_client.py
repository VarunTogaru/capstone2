import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from app.scan.request import Request

logger = logging.getLogger("nmap_insight.helper_client")

DEFAULT_HELPER_URL = "http://127.0.0.1:8765"
HELPER_URL_ENV = "NMAP_HELPER_URL"
TOKEN_ENV = "NMAP_HELPER_TOKEN"
TOKEN_FILE_ENV = "NMAP_HELPER_TOKEN_FILE"
DEFAULT_TOKEN_FILE = Path("/var/run/nmap-insight/helper.token")


def _helper_url() -> str:
    return os.getenv(HELPER_URL_ENV, DEFAULT_HELPER_URL).rstrip("/")


def _helper_token() -> str:
    """Read the shared authentication token from env var or token file."""
    token = os.getenv(TOKEN_ENV)
    if token:
        return token

    token_file = Path(os.getenv(TOKEN_FILE_ENV, str(DEFAULT_TOKEN_FILE)))
    if token_file.exists():
        stored = token_file.read_text().strip()
        if stored:
            return stored

    raise RuntimeError(
        "HELPER_NOT_AVAILABLE: no authentication token found. "
        f"Set {TOKEN_ENV} or ensure {token_file} exists."
    )


def _http_post_json(url: str, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    token = _helper_token()
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _http_error_message(exc: urllib.error.HTTPError) -> str:
    raw = exc.read().decode("utf-8", errors="ignore").strip()
    if not raw:
        return f"Helper request failed ({exc.code})"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw

    detail = parsed.get("detail")
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        if detail.get("errors"):
            return "; ".join(detail["errors"])
        if detail.get("stderr"):
            return str(detail["stderr"])
        if detail.get("code"):
            return str(detail["code"])
    return raw


async def _post_json(path: str, payload: dict[str, Any], timeout_seconds: int = 10) -> dict[str, Any]:
    url = f"{_helper_url()}{path}"
    try:
        return await asyncio.to_thread(_http_post_json, url, payload, timeout_seconds)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_http_error_message(exc)) from exc
    except urllib.error.URLError as exc:
        logger.warning("Helper not reachable: %s", exc)
        raise RuntimeError("HELPER_NOT_AVAILABLE: helper service is not reachable") from exc


def _request_payload(req: Request) -> dict[str, Any]:
    return {
        "request_id": req.request_id,
        "target": req.target,
        "scan_type": req.scan_type,
        "ports": req.ports,
        "extra_args": req.extra_args,
        "timeout_seconds": req.timeout_seconds,
    }


async def run_privileged_nmap_xml(req: Request) -> str:
    logger.info("Requesting privileged scan: target=%s", req.target)
    payload = _request_payload(req)
    validation = await _post_json("/validate", payload, timeout_seconds=10)
    if not validation.get("allowed"):
        errors = validation.get("errors") or ["Privileged request was rejected"]
        logger.error("Privileged scan rejected: %s", errors)
        raise RuntimeError("ELEVATED_FLAG_NOT_ALLOWED: " + "; ".join(errors))

    result = await _post_json("/scan", payload, timeout_seconds=req.timeout_seconds + 5)
    status = result.get("status")
    if status == "canceled":
        raise RuntimeError("Scan was canceled")
    if status != "completed":
        raise RuntimeError("Privileged scan failed")

    xml_output = result.get("xml")
    if not isinstance(xml_output, str) or not xml_output.strip():
        raise RuntimeError("Privileged scan returned empty XML")
    logger.info("Privileged scan completed: target=%s", req.target)
    return xml_output