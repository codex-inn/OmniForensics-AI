import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("OMNIFORENSICS_DATA_DIR", str(ROOT / "data"))).resolve()
EVIDENCE_DIR = DATA_DIR / "evidence"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "omni.sqlite"
MAX_UPLOAD_BYTES = int(os.getenv("OMNIFORENSICS_MAX_UPLOAD_MB", "100")) * 1024 * 1024
ENABLE_OCR = os.getenv("OMNIFORENSICS_ENABLE_OCR", "false").lower() == "true"

def ensure_dirs():
    for path in (DATA_DIR, EVIDENCE_DIR, REPORT_DIR):
        path.mkdir(parents=True, exist_ok=True)
