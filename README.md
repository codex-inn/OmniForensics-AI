# OmniForensics AI — GitHub Pages Edition

A browser-only educational scene-triage prototype. **No Python backend, Google Cloud, Render, database, or API endpoint is required.** The website analyzes selected files locally in the browser and creates JSON/PDF reports client-side.

## Live website

https://codex-inn.github.io/OmniForensics-AI/

If the website is not available yet, open **Settings → Pages** in this repository and set **Build and deployment → Source** to **GitHub Actions**. Then open the Actions tab and wait for **Deploy GitHub Pages frontend** to succeed.

## Browser-only features

- Enter case reference, date/time, scene location, incident type, description and investigator observations.
- Select up to five files, each up to 4 MiB.
- Calculate SHA-256 with the browser Web Crypto API.
- Identify basic leading-byte signature hints for common file types.
- Read image dimensions when the browser can decode the image.
- Show basic PDF page-count and title/author hints where visible in the PDF bytes. This is not a full PDF parser.
- Flag missing incident details, unknown signatures and matching file hashes.
- Generate a downloadable JSON report and a simple PDF report in the browser.
- No analysis request is sent to a backend; no case history or server-side file storage is implemented.

## Privacy and limitations

Files are read by JavaScript in the user's browser and are not uploaded by this application. Analysis results are held in page memory until cleared or the page is closed. This is not a guarantee that the user's device, browser, extensions, network, screenshots, or downloaded reports retain nothing. Use a trusted device and authorized demo data.

This is educational triage, not a certified forensic acquisition or examination system. File signatures are only hints. Hashes describe the exact bytes processed but do not prove provenance or chain of custody. PDF metadata/page-count checks are best-effort pattern checks and may miss compressed or complex documents. The app does not identify suspects, determine guilt, establish cause of death, reconstruct events, or prove that a crime occurred. Independently verify findings.

## Deployment

GitHub Actions publishes the contents of `app/static/` to GitHub Pages on pushes to `main`. The page uses relative static asset paths and works without a backend. In GitHub, go to **Settings → Pages → Build and deployment → GitHub Actions** if Pages is not already configured.

## Optional local Python backend

The Python/FastAPI files remain in the repository for development/reference, but they are **not used by the GitHub Pages edition**. To run the optional server locally, install Python 3.10+ and run:

~~~bash
python -m pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
~~~

Do not configure the public Pages frontend to call this backend; browser-only mode intentionally makes no network API requests.
