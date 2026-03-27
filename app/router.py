import logging

from fastapi import APIRouter, HTTPException
from app.scan.request import Request
from app.connect.dispatcher import run_scan_xml
from app.connect.parser import parse_nmap_xml
from app.scan.db import save_scan, complete_scan, fail_scan, list_scans, get_scan, generate_id

logger = logging.getLogger("nmap_insight.router")

router = APIRouter(tags=["scan"])


@router.post("/scan")
async def scan(req: Request):
    logger.info("Scan requested: target=%s scan_type=%s privileged=%s", req.target, req.scan_type, req.use_privileged)
    scan_id = req.request_id or generate_id()
    save_scan(scan_id, req.target, req.scan_type, req.ports, req.extra_args, req.use_privileged)
    try:
        xml_text = await run_scan_xml(req)
        result = parse_nmap_xml(xml_text)
        result["scan_id"] = scan_id
        logger.info("Scan completed: target=%s hosts=%d", req.target, len(result.get("hosts", [])))
        complete_scan(scan_id, result)
        return result
    except RuntimeError as e:
        message = str(e)
        logger.error("Scan failed: target=%s error=%s", req.target, message)
        fail_scan(scan_id, message)
        if message.startswith("ELEVATED_FLAG_NOT_ALLOWED"):
            raise HTTPException(status_code=400, detail=message)
        if message.startswith("HELPER_NOT_AVAILABLE"):
            raise HTTPException(status_code=503, detail=message)
        if message.startswith("SCAN_TIMEOUT"):
            raise HTTPException(status_code=408, detail=message)
        raise HTTPException(status_code=500, detail=message)


@router.get("/scans")
async def scan_history():
    return list_scans()


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: str):
    record = get_scan(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record
