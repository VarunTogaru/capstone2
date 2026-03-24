import logging

from fastapi import APIRouter, HTTPException
from app.scan.request import Request
from app.connect.dispatcher import run_scan_xml
from app.connect.parser import parse_nmap_xml

logger = logging.getLogger("nmap_insight.router")

router = APIRouter(tags=["scan"])

@router.post("/scan")
async def scan(req: Request):
    logger.info("Scan requested: target=%s scan_type=%s privileged=%s", req.target, req.scan_type, req.use_privileged)
    try:
        xml_text = await run_scan_xml(req)
        result = parse_nmap_xml(xml_text)
        logger.info("Scan completed: target=%s hosts=%d", req.target, len(result.get("hosts", [])))
        return result
    except RuntimeError as e:
        message = str(e)
        logger.error("Scan failed: target=%s error=%s", req.target, message)
        if message.startswith("ELEVATED_FLAG_NOT_ALLOWED"):
            raise HTTPException(status_code=400, detail=message)
        if message.startswith("HELPER_NOT_AVAILABLE"):
            raise HTTPException(status_code=503, detail=message)
        if message.startswith("SCAN_TIMEOUT"):
            raise HTTPException(status_code=408, detail=message)
        raise HTTPException(status_code=500, detail=message)
