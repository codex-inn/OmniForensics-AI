# OmniForensics AI — Cyber Forensics Workbench

A responsive, browser-only digital evidence triage dashboard hosted on GitHub Pages. No Google Cloud, Render, Python backend, API endpoint, account, database, or case-history service is required for the Pages edition.

## Live website

https://codex-inn.github.io/OmniForensics-AI/

If changes are not visible, check the [GitHub Pages deployment workflow](https://github.com/codex-inn/OmniForensics-AI/actions) and confirm repository **Settings → Pages → Build and deployment → Source** is set to **GitHub Actions**. GitHub documents this configuration in its [Pages deployment guide](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## Dashboard features

- Professional responsive cyber/forensics dashboard with session metrics, quick navigation, readiness checklist and local-only status.
- Incident workspace: case reference, date/time, location, incident category, description and investigator observations.
- Evidence analysis: up to 5 files, 4 MiB each; SHA-256 hashes using Web Crypto; common leading-byte signature hints; image dimensions; basic PDF page-count/title/author byte-pattern hints.
- Follow-up checklist for missing context, unknown signatures and identical file hashes.
- Client-side PDF and JSON report downloads.
- Synthetic demo details for previewing the dashboard.
- Clear session control; no automatic saving, localStorage, case database or backend requests.

## Privacy and limitations

Files are read in the browser and are not uploaded by this app. Analysis data is held in page memory until cleared or the page is closed. The user's device, browser, extensions, network, screenshots, and downloaded reports may independently retain information; this is not a guarantee of zero retention. Use a trusted device and authorized demo data.

This is an educational triage aid, not a certified forensic acquisition system. Signature and PDF metadata checks are best-effort hints; complex PDFs may not be parsed correctly. SHA-256 identifies the bytes processed but does not prove provenance or chain of custody. The tool does not identify suspects, determine guilt, reconstruct events, or prove that a crime occurred. Independently verify all findings.

## Deployment

The dedicated GitHub Actions workflow (`.github/workflows/pages.yml`) publishes only the contents of `app/static/` to GitHub Pages when frontend files change on `main`. All asset paths are relative to the project site, so they work at the repository URL above. The source HTML, CSS, and JavaScript live in `app/static/`.

## Optional Python backend files

Python/FastAPI files remain in the repository for development/reference only. They are not used by the GitHub Pages frontend and are not needed to run this version.
