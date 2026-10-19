import os
from pathlib import Path
from PIL import Image
from io import BytesIO
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
        # A report containing user-supplied angle brackets should render rather than break PDF markup.
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
