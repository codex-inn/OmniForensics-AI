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

## Free split deployment: GitHub Pages + FastAPI backend

The repository includes a static frontend deployment workflow at `.github/workflows/pages.yml`. GitHub Pages serves only the browser UI; FastAPI must run separately on a Python host. The frontend uses `app/static/config.js` to select the API origin.

### 1. Deploy the Python backend on Render (free tier)

1. Sign in to [Render](https://render.com/) and choose **New → Blueprint**.
2. Connect `codex-inn/OmniForensics-AI`, select `main`, and deploy the repository's `render.yaml`.
3. Wait for the service to deploy. Copy the exact service origin, for example `https://your-service-name.onrender.com` (no trailing slash).
4. In the Render service's **Environment** settings, confirm the generated `OMNIFORENSICS_USERNAME` and `OMNIFORENSICS_PASSWORD` are non-empty and private. Keep `OMNIFORENSICS_PUBLIC_MODE=true`.
5. Set `OMNIFORENSICS_CORS_ORIGINS` to the exact browser origin for this project site: `https://codex-inn.github.io`. An origin contains scheme + hostname only; do not include `/OmniForensics-AI/`. If you use a custom domain, add that exact origin too, comma-separated.
6. Save environment changes and wait for the backend to restart. Test `https://YOUR-SERVICE.onrender.com/api/health`; it should return JSON with `"status":"ok"`.

The Render service name in `render.yaml` is a requested name, not proof that the resulting URL is available or deployed. Use the URL Render actually gives you.

### 2. Configure the frontend API URL

1. Open `app/static/config.js` in the GitHub repository.
2. Change `window.OMNIFORENSICS_API_BASE = "";` to the exact Render origin, e.g. `window.OMNIFORENSICS_API_BASE = "https://YOUR-SERVICE.onrender.com";` (no trailing slash).
3. Commit the change to `main`. The GitHub Actions Pages workflow automatically publishes the static frontend when files under `app/static/` change.

### 3. Enable GitHub Pages

1. In the repository, open **Settings → Pages**.
2. Under **Build and deployment**, select **GitHub Actions** as the source.
3. Open the **Actions** tab and wait for **Deploy GitHub Pages frontend** to finish successfully.
4. Open `https://codex-inn.github.io/OmniForensics-AI/`. The frontend should call the Render API. On first API request, it prompts for the shared Render username/password; the credentials are kept in that browser tab's session storage, not committed into the frontend. Refresh the tab to clear them, or close it.
5. If the page cannot connect, verify the backend URL in `config.js`, Render's deployment status, `OMNIFORENSICS_CORS_ORIGINS`, and the browser developer console. CORS values must match the actual page origin exactly.

### CORS and security notes

- CORS is restricted to the configured origin list; do not use wildcard origins for a credential-protected deployment. `Authorization` and `Content-Type` headers and the app's required methods are allowed for cross-origin requests.
- The API uses HTTP Basic authentication in public mode. It is one shared account, not individual users or roles. Never place backend secrets in `config.js`, JavaScript, GitHub Pages, or source control.
- The public health endpoint is intentionally unauthenticated for the host's health check and returns service metadata only.
- Static Pages content is public. Anyone can view the frontend source; only the protected backend should hold case/evidence data.

### Important: free-tier storage is temporary

The free Render service in this repository has **no persistent disk**. SQLite data, uploaded evidence, generated reports and other local files may disappear after a restart, redeploy, sleep/wake cycle or host replacement. Free web services can also sleep and take time to wake. The GitHub Pages site remains published, but it does not store backend evidence.

**Demonstration use only:** do not upload sensitive, irreplaceable, regulated, or real investigative evidence to this free configuration. For reliable use, arrange encrypted persistent storage and backups (for example, a private managed database plus private object storage), review access control and retention, and verify the storage provider's current pricing before use. The local SQLite + local-file design is not multi-instance safe.

## Local-only deployment

For local use, run the FastAPI app using the startup steps above and open `http://127.0.0.1:8000`. The split GitHub Pages + free backend deployment guide above is the supported hosted setup. Do not expose the local-only server directly to the internet.
