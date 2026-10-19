# OmniForensics AI — Stateless Crime Scene Analysis & Report Generator

An educational, stateless investigative triage prototype. Enter incident details and observations, optionally submit up to five files, review basic checks, and download PDF/JSON reports. It does **not** create cases, keep history, use SQLite, or intentionally write submitted files to backend storage.

## Features

- Incident details, scene location, incident date/time, description and investigator observations.
- Per-file SHA-256 and byte size calculated from bytes received.
- Basic leading-byte signature hints for selected file formats.
- Image dimensions/format and selected EXIF metadata where parseable.
- PDF page count and selected embedded metadata where parseable.
- Follow-up checklist for missing details, unknown signatures and identical file hashes.
- Downloadable PDF and JSON reports.
- FastAPI, responsive frontend, configurable CORS, request-size checks and security headers.
- No database, case persistence, evidence directory, server-side report file or case history.

## Scope and limitations

This tool does not autonomously solve crimes, identify suspects, determine guilt, establish cause of death, reconstruct events, or prove that a crime occurred. It is not a certified forensic acquisition tool. SHA-256 records the bytes processed by this app; it does not prove origin or acquisition history. All findings require independent human verification.

## Run locally

Python 3.10+ recommended.

~~~powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

Open http://127.0.0.1:8000. Run tests using \`pytest -q\`.

## GitHub Pages frontend

1. Open repository **Settings → Pages** and set source to **GitHub Actions**.
2. Wait for **Deploy GitHub Pages frontend** to succeed.
3. Expected site URL after Pages is enabled: https://codex-inn.github.io/OmniForensics-AI/

## FastAPI backend on Google Cloud Run

Cloud Run supports source deployment for FastAPI. A Google Cloud project and billing setup are required; check current pricing/free allowances first. Official guide: https://docs.cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-fastapi-service

1. Install the Google Cloud CLI, sign in with \`gcloud init\`, select/create a project, and enable billing.
2. From the repository root, deploy the app (example region Mumbai):

~~~bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com
gcloud run deploy omniforensics-ai --source . --region asia-south1 --allow-unauthenticated --set-env-vars OMNIFORENSICS_CORS_ORIGINS=https://codex-inn.github.io
~~~

3. Copy the URL Cloud Run prints and test \`https://YOUR-SERVICE-URL/api/health\`. It should report \`"mode":"stateless"\`.
4. Edit \`app/static/config.js\` in GitHub to set \`window.OMNIFORENSICS_API_BASE = "https://YOUR-SERVICE-URL";\` using the exact service origin with no trailing slash. Commit; Pages redeploys.
5. Open the Pages URL and test a synthetic incident. If requests fail, check the service URL, CORS origin, Cloud Run logs and browser console.

**Security:** \`--allow-unauthenticated\` makes this demo API publicly callable. Use only synthetic/demo information. For restricted use, configure authenticated Cloud Run invocation or an identity-aware gateway before handling private material. The optional shared Basic auth can be enabled with \`OMNIFORENSICS_PUBLIC_MODE=true\`, \`OMNIFORENSICS_USERNAME\` and \`OMNIFORENSICS_PASSWORD\`; never commit credentials or place secrets in frontend JavaScript. A shared password is not full identity/role management.

## Data handling and temporary-storage limitations

- The application has no database or persistent case store. Uploaded files are sent as base64 inside the request and processed in memory; the application does not intentionally write them or generated reports to backend disk.
- Limit: 5 files per request, each up to 8 MiB by default.
- The application keeps no case history after request completion. The browser and the user's downloaded report can retain a copy.
- **This does not guarantee zero retention throughout the hosting stack.** The provider may collect operational metadata, request/security logs or crash data. Review provider terms and configure logging/retention before submitting any sensitive information.
- Cloud Run instances are temporary and the app does not rely on local storage. Free quotas, account requirements and prices can change; do not assume hosting is always free.
- Do not upload real, sensitive or irreplaceable evidence to a public demo. Use authorized data only.

## API

- \`GET /api/health\`
- \`POST /api/analyze\` — scene details and optional base64 files; returns JSON analysis.
- \`POST /api/report/pdf\` — same body; returns a PDF.

Example body:

~~~json
{"case_reference":"DEMO-01","incident_date":"2026-10-19","location":"Demo location","incident_type":"Property incident","description":"Synthetic demonstration only","observations":"Observation one\\nObservation two","files":[]}
~~~
