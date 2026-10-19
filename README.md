# OmniForensics — File Investigation Lab

A browser-only file analysis workbench hosted on GitHub Pages. It focuses on image, document and other-file investigation. No incident form, case database, backend, account, or Google Cloud service is required.

## Live website

https://codex-inn.github.io/OmniForensics-AI/

## Features

- Select up to 10 files, each up to 4 MiB.
- Classify common images, PDF and office/document formats, text files, archives, media, and executable signatures using signature and extension hints.
- Compute SHA-256 hashes with the browser Web Crypto API.
- Inspect image dimensions when browser decoding is supported.
- Best-effort PDF page-count/title/author hints from visible PDF bytes.
- Preview samples of text/CSV/JSON/XML/RTF files, capped to the first 64 KiB.
- Highlight unknown signatures, extension-only classification, parse issues and duplicate hashes.
- Download client-generated PDF and JSON investigation reports.
- Optional analyst notes and clear-session action. No uploads, network analysis calls, localStorage, cookies, database or server-side case history.

## Privacy and limitations

Files are processed in the browser and are not uploaded by this app. Results stay in page memory until cleared or the page is closed. Browser, device, extensions, network, screenshots and downloaded reports may independently retain data. Use authorized data and a trusted device.

This is rule-based educational triage, not certified forensic software and not an AI/ML model. Signatures, extensions, metadata and text previews are clues, not proof of authenticity, authorship, timeline or wrongdoing. PDF parsing is a limited byte-pattern scan; compressed and complex PDFs may hide metadata. Hashes identify the bytes processed but do not prove origin or chain of custody. Independently verify all findings.

## Deployment

The GitHub Actions workflow `.github/workflows/pages.yml` publishes only `app/static/` to GitHub Pages when frontend files change on `main`. Repository Settings → Pages → Build and deployment → Source should be set to **GitHub Actions**.

## Optional Python backend

Python/FastAPI files remain in the repository for reference and local development. They are not used by the GitHub Pages edition.
