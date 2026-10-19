# OmniForensics AI — Local-First Digital Investigation Workbench

An educational prototype for authorized evidence intake, review and reporting. Evidence files are stored locally; there is no cloud upload feature. Run only on a trusted computer and keep the service bound to localhost.

## Implemented features

- FastAPI browser workbench with case creation, listing and text search.
- Local evidence upload, inventory and SHA-256 intake hashes; size limits and sanitized display filenames.
- Evidence search by filename, hash, MIME hint, source/handler text and tag; optional case filter.
- Provenance fields for tags, source/acquisition notes, collector and acquisition time.
- Chain-of-custody event records with handler, location, action, details, time and linked audit event hash.
- On-demand evidence integrity check (match, mismatch, missing).
- Conservative byte-signature hints for common images, PDF, ZIP, some audio/video, PCAP and executable formats. Not a full parser or malware scanner.
- Image format, dimensions, color mode and available EXIF metadata.
- Optional OCR using Tesseract + pytesseract. PDF metadata uses pypdf.
- Optional YOLO object detection on images when a local model path is configured.
- Optional OpenCV video metadata and bounded sampling of up to 12 evenly spaced frames; if YOLO is configured, sampled frames can be analyzed with timestamped detections.
- Unified chronological timeline of evidence, notes and audit events.
- Deterministic correlation suggestions: identical SHA-256 groups and repeated filenames within a case.
- Hash-linked audit events with an endpoint that checks the chain.
- PDF report and downloadable JSON manifest containing evidence hashes, analysis metadata, provenance, custody records, notes and audit event references.
- Automated tests and GitHub Actions CI.

## Not implemented / not certified

- Full-frame CCTV analysis, continuous object tracking, reliable camera/object counting across time, audio transcription, facial recognition or identity matching.
- Full disk/mobile acquisition, full email body/attachment analysis, advanced document malware analysis, full PCAP protocol/stream analysis or automated semantic cross-evidence correlation.
- Certified forensic acquisition, external timestamping, digitally signed/immutable audit logs, application-level encryption, user authentication, role-based access or production multi-user deployment.
- Attribution of a person, proof of a crime, or reliable location inference from an image.

## Requirements and startup

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

## Optional analysis engines

### OCR

Install the Tesseract executable and `pytesseract`, set `OMNIFORENSICS_ENABLE_OCR=true`, then restart the app. OCR can omit or misread text.

### Video sampling

Install `opencv-python-headless`. The app reads basic video dimensions, frame rate, frame count and duration, then samples up to 12 evenly spaced frames. This can miss brief events and is not continuous CCTV analytics.

### YOLO object detection

Install `ultralytics`, obtain a model you are licensed and authorized to use, and set `OMNIFORENSICS_YOLO_MODEL` to its local path. No model is bundled or downloaded automatically. Predictions are model-dependent suggestions, not proof.

Example PowerShell:

~~~powershell
$env:OMNIFORENSICS_YOLO_MODEL = "C:\models\your-model.pt"
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

## API highlights

- `GET /api/health`
- `GET/POST /api/cases` (case search: `?q=...`)
- `GET /api/cases/{case_id}`
- `POST /api/cases/{case_id}/evidence`
- `GET /api/evidence/search?q=...&tag=...&case_id=...`
- `GET /api/evidence/{evidence_id}`
- `PATCH /api/evidence/{evidence_id}` (provenance fields)
- `GET /api/evidence/{evidence_id}/integrity`
- `GET/POST /api/evidence/{evidence_id}/custody`
- `POST /api/cases/{case_id}/notes`
- `GET /api/cases/{case_id}/timeline`
- `GET /api/cases/{case_id}/correlations`
- `GET /api/cases/{case_id}/manifest.json`
- `GET /api/cases/{case_id}/audit`
- `GET /api/cases/{case_id}/audit/integrity`
- `GET /api/cases/{case_id}/report`

## Storage and safety

- Bind to `127.0.0.1`. **Do not expose this prototype to a network or the public internet**: it has no authentication, authorization or TLS.
- Evidence is stored in `data/evidence/`; metadata and notes are stored in SQLite under the configured data directory.
- Uploaded evidence is not encrypted by this app. Use full-disk encryption, restrict OS account access and protect backups.
- Preserve originals and use working copies where appropriate. Provenance and custody records help document handling but are only as reliable as the information entered by the operator.
- SHA-256 matching means current file bytes match the intake hash recorded by this app; it does not prove source, author, acquisition process or truth of contents.
- The JSON manifest is not digitally signed. Audit hash chaining provides tamper evidence, not immutability: an administrator able to rewrite the database can recompute the chain.
- Treat all machine-generated results as leads. Independently verify detections and metadata before relying on them.
