import os
from pathlib import Path
from fastapi.testclient import TestClient

def test_case_upload_hash_report(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNIFORENSICS_DATA_DIR", str(tmp_path / "data"))
    from app import config
    config.DATA_DIR = Path(os.environ["OMNIFORENSICS_DATA_DIR"])
    config.EVIDENCE_DIR = config.DATA_DIR / "evidence"
    config.REPORT_DIR = config.DATA_DIR / "reports"
    config.DB_PATH = config.DATA_DIR / "test.sqlite"
    from app.main import app
    with TestClient(app) as client:
        response = client.post("/api/cases", json={"title": "Test case", "description": "test"})
        assert response.status_code == 200
        case_id = response.json()["id"]
        response = client.post(f"/api/cases/{case_id}/evidence",
            files={"file": ("note.txt", b"sample evidence", "text/plain")})
        assert response.status_code == 200
        evidence_id = response.json()["id"]
        assert len(response.json()["sha256"]) == 64
        assert client.get(f"/api/evidence/{evidence_id}/integrity").json()["status"] == "match"
        assert client.get(f"/api/cases/{case_id}/report").headers["content-type"] == "application/pdf"
