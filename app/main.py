import json, re, uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .config import ensure_dirs, EVIDENCE_DIR, REPORT_DIR, MAX_UPLOAD_BYTES
from .db import connect, init_db
from .forensics import inspect_file, sha256_file
from .reports import build_report

app = FastAPI(title="OmniForensics AI", version="0.1.0")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

def now():
    return datetime.now(timezone.utc).isoformat()

def audit(case_id, event, details):
    with connect() as conn:
        conn.execute("INSERT INTO audit(case_id,event,details_json,created_at) VALUES(?,?,?,?)",
                     (case_id, event, json.dumps(details), now()))

def case_or_404(case_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Case not found")
    return dict(row)

@app.on_event("startup")
def startup():
    ensure_dirs()
    init_db()

@app.get("/", response_class=HTMLResponse)
def home():
    return (STATIC / "index.html").read_text(encoding="utf-8")

class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)

class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)

@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "local-first", "max_upload_bytes": MAX_UPLOAD_BYTES}

@app.post("/api/cases")
def create_case(data: CaseIn):
    title = data.title.strip()
    if not title:
        raise HTTPException(422, "Case title cannot be blank")
    case_id = "CASE-" + uuid.uuid4().hex[:10].upper()
    created = now()
    with connect() as conn:
        conn.execute("INSERT INTO cases VALUES(?,?,?,?)", (case_id, title, data.description.strip(), created))
    audit(case_id, "case_created", {"title": title})
    return {"id": case_id, "title": title, "description": data.description.strip(), "created_at": created}

@app.get("/api/cases")
def list_cases():
    with connect() as conn:
        rows = conn.execute("""SELECT c.*, COUNT(e.id) evidence_count FROM cases c
          LEFT JOIN evidence e ON e.case_id=c.id GROUP BY c.id ORDER BY c.created_at DESC""").fetchall()
    return [dict(row) for row in rows]

@app.get("/api/cases/{case_id}")
def case_detail(case_id: str):
    case = case_or_404(case_id)
    with connect() as conn:
        evidence = [dict(row) for row in conn.execute(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,)).fetchall()]
        notes = [dict(row) for row in conn.execute(
            "SELECT * FROM notes WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()]
    return {"case": case, "evidence": evidence, "notes": notes}

@app.post("/api/cases/{case_id}/evidence")
async def upload(case_id: str, file: UploadFile = File(...)):
    case_or_404(case_id)
    name = Path(file.filename or "upload.bin").name
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", name)[:180] or "upload.bin"
    evidence_id = "EVD-" + uuid.uuid4().hex[:12].upper()
    folder = EVIDENCE_DIR / case_id
    folder.mkdir(parents=True, exist_ok=True)
    stored = evidence_id + Path(name).suffix[:16]
    destination = folder / stored
    total = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "Upload exceeds configured size limit")
                output.write(chunk)
        if total == 0:
            raise HTTPException(400, "Empty files are not accepted")
        analysis = inspect_file(destination, name)
        created = now()
        with connect() as conn:
            conn.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)",
                (evidence_id, case_id, name, stored, analysis["sha256"], total,
                 analysis["mime_type"], created, json.dumps(analysis, ensure_ascii=False)))
        audit(case_id, "evidence_uploaded", {"evidence_id": evidence_id, "sha256": analysis["sha256"], "size_bytes": total})
        return {"id": evidence_id, "case_id": case_id, "original_name": name, "sha256": analysis["sha256"],
                "size_bytes": total, "mime_type": analysis["mime_type"], "uploaded_at": created, "analysis": analysis}
    except Exception:
        if destination.exists():
            destination.unlink()
        raise
    finally:
        await file.close()

@app.get("/api/evidence/{evidence_id}")
def evidence_detail(evidence_id: str):
    with connect() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    result = dict(row)
    result["analysis"] = json.loads(result.pop("analysis_json"))
    return result

@app.get("/api/evidence/{evidence_id}/integrity")
def verify(evidence_id: str):
    with connect() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    item = dict(row)
    path = EVIDENCE_DIR / item["case_id"] / item["stored_name"]
    if not path.exists():
        return {"evidence_id": evidence_id, "status": "missing", "expected_sha256": item["sha256"], "actual_sha256": None}
    actual = sha256_file(path)
    status = "match" if actual == item["sha256"] else "mismatch"
    audit(item["case_id"], "integrity_check", {"evidence_id": evidence_id, "status": status})
    return {"evidence_id": evidence_id, "status": status, "expected_sha256": item["sha256"], "actual_sha256": actual}

@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: str, data: NoteIn):
    case_or_404(case_id)
    body = data.body.strip()
    if not body:
        raise HTTPException(422, "Note cannot be blank")
    created = now()
    with connect() as conn:
        cursor = conn.execute("INSERT INTO notes(case_id,body,created_at) VALUES(?,?,?)", (case_id, body, created))
        note_id = cursor.lastrowid
    audit(case_id, "note_added", {"note_id": note_id})
    return {"id": note_id, "case_id": case_id, "body": body, "created_at": created}

@app.get("/api/cases/{case_id}/audit")
def audit_list(case_id: str):
    case_or_404(case_id)
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit WHERE case_id=? ORDER BY id", (case_id,)).fetchall()
    return [dict(row) for row in rows]

@app.get("/api/cases/{case_id}/report")
def report(case_id: str):
    case = case_or_404(case_id)
    with connect() as conn:
        evidence = [dict(row) for row in conn.execute(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()]
        notes = [dict(row) for row in conn.execute(
            "SELECT * FROM notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
    path = REPORT_DIR / (case_id + ".pdf")
    build_report(path, case, evidence, notes)
    audit(case_id, "report_generated", {"filename": path.name})
    return FileResponse(path, media_type="application/pdf", filename=case_id + "-forensic-report.pdf")
