import base64
import hashlib
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def payload(files=None):
    return {"case_reference":"DEMO-01","incident_date":"2026-10-19","location":"Demo location","incident_type":"Property incident","description":"Synthetic demonstration only","observations":"Door found open\nNo suspect identified","files":files or []}

def test_health_stateless():
    data=client.get("/api/health").json()
    assert data["mode"]=="stateless"
    assert data["persistent_case_storage"] is False

def test_analyze_text_only():
    r=client.post("/api/analyze",json=payload())
    assert r.status_code==200
    assert r.json()["privacy"]["database_used"] is False
    assert r.json()["file_count"]==0

def test_hash_upload_in_memory():
    raw=b"safe demo bytes"
    files=[{"filename":"sample.bin","content_base64":base64.b64encode(raw).decode()}]
    r=client.post("/api/analyze",json=payload(files))
    assert r.status_code==200
    assert r.json()["files"][0]["sha256"]==hashlib.sha256(raw).hexdigest()

def test_bad_base64_rejected():
    r=client.post("/api/analyze",json=payload([{"filename":"bad.bin","content_base64":"%%%"}]))
    assert r.status_code==422

def test_pdf_report():
    r=client.post("/api/report/pdf",json=payload())
    assert r.status_code==200
    assert r.headers["content-type"]=="application/pdf"
    assert r.content.startswith(b"%PDF")


from pypdf import PdfReader
import io

def test_root_serves_dashboard_with_valid_asset_paths():
    r = client.get("/")
    assert r.status_code == 200
    assert "Cyber Forensics Workbench" in r.text
    assert 'href="/static/styles.css"' in r.text
    assert 'src="/static/app.js"' in r.text
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200

def test_pdf_report_is_parseable_and_has_pages():
    r = client.post("/api/report/pdf", json=payload())
    assert r.status_code == 200
    reader = PdfReader(io.BytesIO(r.content))
    assert len(reader.pages) >= 1
    assert "OmniForensics AI" in (reader.pages[0].extract_text() or "")

def test_empty_file_is_rejected():
    r = client.post("/api/analyze", json=payload([{"filename":"empty.bin","content_base64":""}]))
    assert r.status_code == 422
