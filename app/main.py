import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("nmap_insight")

from fastapi import FastAPI
from fastapi.responses import FileResponse
from app.router import router
from app.scan.db import init_db

app = FastAPI()
app.include_router(router)

init_db()

if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    BASE_DIR = Path(sys._MEIPASS) / "app"  # For when running PyInstaller
else:
    BASE_DIR = Path(__file__).resolve().parent  # For running normally

INDEX_FILE = BASE_DIR / "static" / "index.html"

@app.get("/", include_in_schema=False)
async def serve_frontend() -> FileResponse:
    # Serve the local demo UI from the app.
    return FileResponse(INDEX_FILE)

@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    import multiprocessing
    multiprocessing.freeze_support()
    logger.info("Starting Nmap Insight on 127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
