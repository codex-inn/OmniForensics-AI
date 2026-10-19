# OmniForensics AI — Local-First Digital Investigation Workbench

A runnable educational prototype for authorized digital-forensics workflows.

## Implemented
- FastAPI web app and responsive browser UI.
- Case creation/listing, evidence upload and inventory.
- Local evidence files + SQLite case metadata.
- Upload size limit, safe basename handling, SHA-256 hashing and integrity re-check.
- Image dimensions, format, mode and available EXIF extraction.
- Optional OCR integration (requires `pytesseract` plus the Tesseract executable).
- Case notes, basic audit events and PDF case report.
- Automated test covering case creation, upload, hash verification and PDF report.

## Not implemented yet
- Automatic scene/object detection, reliable CCTV-camera detection, video analytics, face recognition.
- Full disk/mobile forensics, email parsing, PCAP protocol analysis, advanced document malware analysis, cross-evidence timeline correlation.
- Certified forensic acquisition, cryptographically signed/immutable audit logs, encryption at application layer, user authentication and role-based access.
- Attribution of a person, proof of a crime, or reliable location inference from an image.

## Requirements
Python 3.10+ on Windows/macOS/Linux.

### Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000

### macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Test
```bash
pytest -q
```

### Optional OCR
Install Tesseract OCR for your OS, then `pip install pytesseract`, set `OMNIFORENSICS_ENABLE_OCR=true`, and restart the server. OCR output can be inaccurate.

## Storage and safety
- Recommended command binds to `127.0.0.1`. Do not expose this prototype to a network: it has no authentication or TLS.
- Evidence is stored in `data/evidence/`; metadata and notes are in `data/omni.sqlite`.
- The prototype does not encrypt evidence files. Use full-disk encryption and restrict access to your OS account.
- Keep originals unchanged and work on copies when possible.
- A SHA-256 match proves only that bytes match the recorded upload hash, not authenticity or truth.
- Treat AI outputs as leads and verify them independently.
