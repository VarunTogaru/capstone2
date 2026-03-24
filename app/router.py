from fastapi import APIRouter, HTTPException
from app.scan.request import Request
from app.connect.dispatcher import run_scan_xml
from app.connect.parser import parse_nmap_xml

router = APIRouter(tags=["scan"])

@router.post("/scan")
async def scan(req: Request):
    try:
        xml_text = await run_scan_xml(req)
        return parse_nmap_xml(xml_text)
    except RuntimeError as e:
        message = str(e)
        if message.startswith("ELEVATED_FLAG_NOT_ALLOWED"):
            raise HTTPException(status_code=400, detail=message)
        if message.startswith("HELPER_NOT_AVAILABLE"):
            raise HTTPException(status_code=503, detail=message)
        if message.startswith("SCAN_TIMEOUT"):
            raise HTTPException(status_code=408, detail=message)
        raise HTTPException(status_code=500, detail=message)
