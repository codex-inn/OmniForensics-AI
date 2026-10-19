# OmniForensics AI — Local-First Digital Investigation Workbench

An educational prototype for authorized evidence intake and review. It is designed to keep uploaded files on the local machine and to make the boundary between observed metadata and conclusions explicit.

## Implemented

- FastAPI web app with responsive browser interface and health endpoint.
- Case creation/listing, evidence inventory, notes and basic case management.
- Local evidence files and SQLite metadata; configurable upload size limit; sanitized original names.
- SHA-256 hash recorded at intake and re-check on demand, with match, mismatch, or missing status.
- Conservative byte-signature hints for common images, PDF, ZIP, some audio/video, PCAP and executable formats. Signature detection is a hint, not a full parser or malware scan.
- Image format, dimensions, color mode and available EXIF metadata.
- Optional OCR using Tesseract + pytesseract.
- Optional YOLO-based object detection on images when a model path is configured. Results include class labels, confidence and bounding boxes; accuracy depends on the model and image quality.
- Unified chronological case timeline for uploaded evidence, notes and audit events.
- Hash-linked audit events and an endpoint that checks the chain for tampering.
- PDF case reports containing evidence hashes, analysis metadata, notes and audit event references.
- Automated tests for cases, image metadata, upload, integrity, timeline, audit chain and PDF output.
- GitHub Actions test workflow.

## Not implemented / not certified

- Reliable CCTV-camera detection or complete video/CCTV analytics, multi-frame tracking, audio transcription, facial recognition, or identity matching.
- Full disk/mobile acquisition, email parsing, advanced document malware analysis, full PCAP protocol analysis, or automated cross-evidence correlation beyond a basic timestamped timeline.
- Certified forensic acquisition, external timestamping, signed immutable audit logs, application-level encryption, user authentication, role-based access, or production multi-user deployment.
- Attribution of a person, proof of a crime, or reliable location inference from an image.

## Requirements

Python 3.10+ on Windows/macOS/Linux.

### Windows PowerShell

~~~powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

### macOS/Linux

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

Open http://127.0.0.1:8000

### Test

~~~bash
pytest -q
~~~

## Optional image analysis

### OCR

1. Install the Tesseract OCR executable for your operating system.
2. Install pytesseract in the active Python environment: pip install pytesseract.
3. Set OMNIFORENSICS_ENABLE_OCR=true in your environment and restart the app.

OCR may omit or misread text. Review source images.

### YOLO object detection

1. Install a compatible Ultralytics package in your active environment: pip install ultralytics.
2. Obtain a model you are licensed and authorized to use, and store it locally.
3. Set OMNIFORENSICS_YOLO_MODEL to that local model path before starting the app.
4. Upload an image. The application will attempt detection and store labels, confidence values and bounding boxes with the evidence analysis.

Example PowerShell session:

~~~powershell
$env:OMNIFORENSICS_YOLO_MODEL = "C:\models\your-model.pt"
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

The model path is optional. Without it, detection reports not_configured. No pretrained model is bundled or downloaded automatically. Predictions are model-dependent suggestions, not proof.

## Configuration

- OMNIFORENSICS_DATA_DIR: local data directory (default: repository data/).
- OMNIFORENSICS_MAX_UPLOAD_MB: maximum upload size in MiB (default: 100).
- OMNIFORENSICS_ENABLE_OCR: true to attempt optional OCR (default: false).
- OMNIFORENSICS_YOLO_MODEL: optional local Ultralytics-compatible model path.

## API highlights

- GET /api/health
- GET/POST /api/cases
- GET /api/cases/{case_id}
- POST /api/cases/{case_id}/evidence
- GET /api/evidence/{evidence_id}
- GET /api/evidence/{evidence_id}/integrity
- POST /api/cases/{case_id}/notes
- GET /api/cases/{case_id}/timeline
- GET /api/cases/{case_id}/audit
- GET /api/cases/{case_id}/audit/integrity
- GET /api/cases/{case_id}/report

## Storage and safety

- Bind to 127.0.0.1. **Do not expose this prototype to a network or the public internet**: it has no authentication, authorization or TLS.
- Evidence is stored in data/evidence/; metadata and notes are in data/omni.sqlite.
- Uploaded evidence is not encrypted by this app. Use full-disk encryption, restrict OS account access and protect backups.
- Preserve originals and use working copies where appropriate. Record the evidence source, acquisition method, handler and times separately in your documented procedure.
- SHA-256 matching means the current file bytes match the hash recorded by this app; it does not prove the source, author, acquisition process or truth of contents.
- Hash-linked audit records can reveal accidental or partial modification, but an administrator who can rewrite the database can recompute the chain. This is not a cryptographically signed, immutable or independently timestamped log.
- Treat all machine-generated results as leads. Independently verify detections and metadata before relying on them.
