import os
import json
from pathlib import Path
from io import BytesIO
from PIL import Image
from fastapi.testclient import TestClient

def setup_client(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNIFORENSICS_DATA_DIR", str(tmp_path / "data"))
    from app import config
    config.DATA_DIR = Path(os.environ["OMNIFORENSICS_DATA_DIR"])
    config.EVIDENCE_DIR = config.DATA_DIR / "evidence"
    config.REPORT_DIR = config.DATA_DIR / "reports"
    config.DB_PATH = config.DATA_DIR / "test.sqlite"
    from app.main import app
    import app.main as main_module
    main_module.EVIDENCE_DIR = config.EVIDENCE_DIR
    main_module.REPORT_DIR = config.REPORT_DIR
    main_module.MAX_UPLOAD_BYTES = config.MAX_UPLOAD_BYTES
    return TestClient(app)

def test_case_upload_hash_timeline_audit_and_report(tmp_path, monkeypatch):
    with setup_client(tmp_path, monkeypatch) as client:
        response = client.post("/api/cases", json={"title": "Test <case>", "description": "test & review"})
        assert response.status_code == 200
        case_id = response.json()["id"]
        response = client.post(f"/api/cases/{case_id}/evidence",
            files={"file": ("note.txt", b"sample evidence", "text/plain")})
        assert response.status_code == 200
        evidence_id = response.json()["id"]
        assert len(response.json()["sha256"]) == 64
        assert response.json()["analysis"]["signature_mime_type"] is None
        assert client.get(f"/api/evidence/{evidence_id}/integrity").json()["status"] == "match"
        timeline = client.get(f"/api/cases/{case_id}/timeline")
        assert timeline.status_code == 200
        assert any(item["type"] == "evidence" for item in timeline.json())
        assert client.post(f"/api/cases/{case_id}/notes", json={"body": "Review metadata"}).status_code == 200
        audit_result = client.get(f"/api/cases/{case_id}/audit/integrity").json()
        assert audit_result["status"] == "verified"
        report = client.get(f"/api/cases/{case_id}/report")
        assert report.status_code == 200
        assert report.headers["content-type"] == "application/pdf"
        assert report.content.startswith(b"%PDF")
        assert client.get(f"/api/cases/{case_id}/audit/integrity").json()["status"] == "verified"

def test_image_signature_and_metadata(tmp_path, monkeypatch):
    buffer = BytesIO()
    Image.new("RGB", (3, 2), "white").save(buffer, format="PNG")
    with setup_client(tmp_path, monkeypatch) as client:
        case_id = client.post("/api/cases", json={"title": "Image case"}).json()["id"]
        response = client.post(f"/api/cases/{case_id}/evidence",
            files={"file": ("photo.png", buffer.getvalue(), "image/png")})
        assert response.status_code == 200
        body = response.json()
        assert body["analysis"]["signature_mime_type"] == "image/png"
        assert body["analysis"]["image"]["width"] == 3
        assert body["analysis"]["image"]["height"] == 2

def test_empty_upload_rejected(tmp_path, monkeypatch):
    with setup_client(tmp_path, monkeypatch) as client:
        case_id = client.post("/api/cases", json={"title": "Empty upload test"}).json()["id"]
        response = client.post(f"/api/cases/{case_id}/evidence",
            files={"file": ("empty.txt", b"", "text/plain")})
        assert response.status_code == 400

def test_evidence_provenance_custody_search_manifest_and_correlations(tmp_path, monkeypatch):
    with setup_client(tmp_path, monkeypatch) as client:
        case_id = client.post("/api/cases", json={"title": "Evidence case"}).json()["id"]
        payload = b"same exact evidence bytes"
        first = client.post(f"/api/cases/{case_id}/evidence", files={"file": ("capture.log", payload, "text/plain")}).json()
        second = client.post(f"/api/cases/{case_id}/evidence", files={"file": ("copy.log", payload, "text/plain")}).json()
        evidence_id = first["id"]
        updated = client.patch(f"/api/evidence/{evidence_id}", json={
            "tags": "network, incident, network", "source_description": "Authorized lab export",
            "collected_by": "Investigator A", "acquired_at": "2026-10-19T10:00:00+05:30"})
        assert updated.status_code == 200
        assert updated.json()["tags"] == "network,incident"
        custody = client.post(f"/api/evidence/{evidence_id}/custody", json={
            "action": "Transferred to secure storage", "handler": "Investigator A",
            "location": "Local evidence folder", "details": "Read-only working copy prepared"})
        assert custody.status_code == 200
        assert custody.json()["audit_event_hash"]
        assert len(client.get(f"/api/evidence/{evidence_id}/custody").json()) == 1
        search = client.get("/api/evidence/search", params={"q": "capture", "tag": "network", "case_id": case_id})
        assert search.status_code == 200 and len(search.json()) == 1
        correlations = client.get(f"/api/cases/{case_id}/correlations").json()
        assert len(correlations["duplicate_hash_groups"]) == 1
        assert {x["id"] for x in correlations["duplicate_hash_groups"][0]["items"]} == {evidence_id, second["id"]}
        manifest = client.get(f"/api/cases/{case_id}/manifest.json")
        assert manifest.status_code == 200
        assert "attachment;" in manifest.headers.get("content-disposition", "")
        document = manifest.json()
        assert document["evidence"][0]["sha256_at_intake"]
        assert document["evidence"][0]["custody"][0]["action"] == "Transferred to secure storage"
        assert any(e["event"] == "custody_event" for e in document["audit_events"])

def test_case_search_and_health_feature_list(tmp_path, monkeypatch):
    with setup_client(tmp_path, monkeypatch) as client:
        client.post("/api/cases", json={"title": "Network Incident", "description": "authorized capture"})
        client.post("/api/cases", json={"title": "Photo Review"})
        result = client.get("/api/cases", params={"q": "Network"})
        assert len(result.json()) == 1
        health = client.get("/api/health").json()
        assert health["version"] == "0.4.0"
        assert "custody_log" in health["features"]

def test_email_header_and_archive_triage(tmp_path, monkeypatch):
    import zipfile
    archive_buffer = BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("sample.txt", "safe test data")
    email_bytes = b"From: sender@example.test\r\nTo: receiver@example.test\r\nSubject: Test case\r\nMessage-ID: <test-1@example.test>\r\n\r\nbody"
    with setup_client(tmp_path, monkeypatch) as client:
        case_id = client.post("/api/cases", json={"title": "File triage"}).json()["id"]
        email = client.post(f"/api/cases/{case_id}/evidence", files={"file": ("sample.eml", email_bytes, "message/rfc822")})
        assert email.status_code == 200
        assert email.json()["analysis"]["email"]["status"] == "headers_parsed"
        assert email.json()["analysis"]["email"]["subject"] == "Test case"
        zipped = client.post(f"/api/cases/{case_id}/evidence", files={"file": ("sample.zip", archive_buffer.getvalue(), "application/zip")})
        assert zipped.status_code == 200
        triage = zipped.json()["analysis"]["archive"]
        assert triage["status"] == "listed"
        assert triage["entries_preview"][0]["name"] == "sample.txt"

def test_public_mode_requires_credentials(tmp_path, monkeypatch):
    import base64
    monkeypatch.setenv("OMNIFORENSICS_PUBLIC_MODE", "true")
    monkeypatch.setenv("OMNIFORENSICS_USERNAME", "investigator")
    monkeypatch.setenv("OMNIFORENSICS_PASSWORD", "test-only-secret")
    with setup_client(tmp_path, monkeypatch) as client:
        assert client.get("/api/health").status_code == 200
        denied = client.get("/")
        assert denied.status_code == 401
        assert "WWW-Authenticate" in denied.headers
        token = base64.b64encode(b"investigator:test-only-secret").decode("ascii")
        allowed = client.get("/", headers={"Authorization": "Basic " + token})
        assert allowed.status_code == 200
        assert client.get("/api/cases").status_code == 401
        assert client.get("/api/cases", headers={"Authorization": "Basic " + token}).status_code == 200
