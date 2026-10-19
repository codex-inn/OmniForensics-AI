import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .config import ensure_dirs, EVIDENCE_DIR, REPORT_DIR, MAX_UPLOAD_BYTES
from .db import connect, init_db
from .forensics import inspect_file, sha256_file
from .reports import build_report

app = FastAPI(title="OmniForensics AI", version="0.3.0")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

def now():
    return datetime.now(timezone.utc).isoformat()

def audit(case_id, event, details):
    created = now()
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with connect() as conn:
        previous = conn.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = previous["event_hash"] if previous and previous["event_hash"] else "GENESIS"
        payload = json.dumps({"case_id": case_id, "event": event, "details_json": details_json,
                              "created_at": created, "prev_hash": prev_hash},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        conn.execute("INSERT INTO audit(case_id,event,details_json,created_at,prev_hash,event_hash) VALUES(?,?,?,?,?,?)",
                     (case_id, event, details_json, created, prev_hash, event_hash))
    return event_hash

def case_or_404(case_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Case not found")
    return dict(row)

def evidence_or_404(evidence_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
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

class EvidenceUpdate(BaseModel):
    tags: str = Field(default="", max_length=1000)
    source_description: str = Field(default="", max_length=2000)
    collected_by: str = Field(default="", max_length=200)
    acquired_at: str = Field(default="", max_length=100)

class CustodyIn(BaseModel):
    action: str = Field(min_length=2, max_length=100)
    handler: str = Field(default="", max_length=200)
    location: str = Field(default="", max_length=300)
    details: str = Field(default="", max_length=2000)

@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "local-first", "version": "0.3.0",
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "features": ["sha256", "signature_hints", "image_metadata", "optional_ocr",
                         "optional_yolo_image_detection", "optional_video_sampling", "hash_linked_audit",
                         "case_timeline", "evidence_search", "provenance_fields", "custody_log",
                         "duplicate_hash_correlation", "json_manifest", "pdf_report"]}

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
def list_cases(q: str = Query(default="", max_length=200)):
    pattern = "%" + q.strip() + "%"
    with connect() as conn:
        rows = conn.execute("""SELECT c.*, COUNT(e.id) evidence_count FROM cases c
          LEFT JOIN evidence e ON e.case_id=c.id
          WHERE (?='' OR c.title LIKE ? OR c.description LIKE ? OR c.id LIKE ?)
          GROUP BY c.id ORDER BY c.created_at DESC""",
          (q.strip(), pattern, pattern, pattern)).fetchall()
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
    evidence_recorded = False
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
            conn.execute("""INSERT INTO evidence
                (id,case_id,original_name,stored_name,sha256,size_bytes,detected_mime,uploaded_at,analysis_json,
                 tags,source_description,collected_by,acquired_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (evidence_id, case_id, name, stored, analysis["sha256"], total,
                 analysis["mime_type"], created, json.dumps(analysis, ensure_ascii=False), "", "", "", ""))
        evidence_recorded = True
        audit(case_id, "evidence_uploaded", {"evidence_id": evidence_id, "sha256": analysis["sha256"],
                                             "size_bytes": total, "mime_type": analysis["mime_type"]})
        return {"id": evidence_id, "case_id": case_id, "original_name": name, "sha256": analysis["sha256"],
                "size_bytes": total, "mime_type": analysis["mime_type"], "uploaded_at": created, "analysis": analysis}
    except Exception:
        if not evidence_recorded and destination.exists():
            destination.unlink()
        raise
    finally:
        await file.close()

@app.get("/api/evidence/search")
def search_evidence(q: str = Query(default="", max_length=200), tag: str = Query(default="", max_length=100),
                    case_id: str = Query(default="", max_length=64), limit: int = Query(default=100, ge=1, le=500)):
    qv, tv, cv = q.strip(), tag.strip(), case_id.strip()
    pat = "%" + qv + "%"
    tagpat = "%" + tv + "%"
    with connect() as conn:
        rows = conn.execute("""SELECT e.id,e.case_id,e.original_name,e.sha256,e.size_bytes,e.detected_mime,
             e.uploaded_at,e.tags,e.source_description,e.collected_by,e.acquired_at
             FROM evidence e WHERE (?='' OR e.case_id=?) AND
             (?='' OR e.original_name LIKE ? OR e.sha256 LIKE ? OR e.detected_mime LIKE ? OR
              e.source_description LIKE ? OR e.collected_by LIKE ?) AND
             (?='' OR (',' || lower(e.tags) || ',') LIKE lower(?))
             ORDER BY e.uploaded_at DESC LIMIT ?""",
             (cv, cv, qv, pat, pat, pat, pat, pat, tv, "%," + tv + ",%", limit)).fetchall()
    return [dict(row) for row in rows]

@app.get("/api/evidence/{evidence_id}")
def evidence_detail(evidence_id: str):
    result = evidence_or_404(evidence_id)
    result["analysis"] = json.loads(result.pop("analysis_json"))
    return result

@app.patch("/api/evidence/{evidence_id}")
def update_evidence(evidence_id: str, data: EvidenceUpdate):
    item = evidence_or_404(evidence_id)
    values = {"tags": ",".join(dict.fromkeys(t.strip() for t in data.tags.split(",") if t.strip())),
              "source_description": data.source_description.strip(),
              "collected_by": data.collected_by.strip(), "acquired_at": data.acquired_at.strip()}
    with connect() as conn:
        conn.execute("""UPDATE evidence SET tags=?,source_description=?,collected_by=?,acquired_at=? WHERE id=?""",
                     (values["tags"], values["source_description"], values["collected_by"], values["acquired_at"], evidence_id))
    audit(item["case_id"], "evidence_provenance_updated", {"evidence_id": evidence_id, **values})
    return {"evidence_id": evidence_id, **values}

@app.post("/api/evidence/{evidence_id}/custody")
def add_custody(evidence_id: str, data: CustodyIn):
    item = evidence_or_404(evidence_id)
    created = now()
    event_hash = audit(item["case_id"], "custody_event", {"evidence_id": evidence_id, "action": data.action.strip(),
                       "handler": data.handler.strip(), "location": data.location.strip(), "details": data.details.strip()})
    with connect() as conn:
        cursor = conn.execute("""INSERT INTO custody(evidence_id,action,handler,location,details,created_at,audit_event_hash)
          VALUES(?,?,?,?,?,?,?)""", (evidence_id, data.action.strip(), data.handler.strip(), data.location.strip(),
          data.details.strip(), created, event_hash))
        record_id = cursor.lastrowid
    return {"id": record_id, "evidence_id": evidence_id, "action": data.action.strip(), "created_at": created,
            "audit_event_hash": event_hash}

@app.get("/api/evidence/{evidence_id}/custody")
def custody_list(evidence_id: str):
    evidence_or_404(evidence_id)
    with connect() as conn:
        rows = conn.execute("SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()
    return [dict(row) for row in rows]

@app.get("/api/evidence/{evidence_id}/integrity")
def verify(evidence_id: str):
    item = evidence_or_404(evidence_id)
    path = EVIDENCE_DIR / item["case_id"] / item["stored_name"]
    if not path.exists():
        result = {"evidence_id": evidence_id, "status": "missing", "expected_sha256": item["sha256"], "actual_sha256": None}
    else:
        actual = sha256_file(path)
        result = {"evidence_id": evidence_id, "status": "match" if actual == item["sha256"] else "mismatch",
                  "expected_sha256": item["sha256"], "actual_sha256": actual}
    audit(item["case_id"], "integrity_check", {"evidence_id": evidence_id, "status": result["status"]})
    return result

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

@app.get("/api/cases/{case_id}/audit/integrity")
def audit_integrity(case_id: str):
    case_or_404(case_id)
    with connect() as conn:
        rows = [dict(row) for row in conn.execute("SELECT * FROM audit ORDER BY id").fetchall()]
    previous = "GENESIS"
    checked = 0
    legacy = 0
    for row in rows:
        if not row.get("event_hash"):
            legacy += 1
            continue
        payload = json.dumps({"case_id": row["case_id"], "event": row["event"],
                              "details_json": row["details_json"], "created_at": row["created_at"],
                              "prev_hash": previous}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if row.get("prev_hash") != previous or row.get("event_hash") != expected:
            return {"status": "tampered_or_invalid", "checked_events": checked, "legacy_events": legacy,
                    "failed_event_id": row["id"],
                    "note": "Unhashed legacy events are excluded; the hash-linked portion can still be checked."}
        previous = row["event_hash"]
        checked += 1
    return {"status": "verified_with_legacy" if legacy else "verified",
            "checked_events": checked, "legacy_events": legacy,
            "note": "Hash-linked tamper evidence only; legacy events are not verified and database administrators can rewrite the entire chain."}

@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id: str):
    case_or_404(case_id)
    with connect() as conn:
        evidence = conn.execute("SELECT id AS ref_id, original_name AS label, uploaded_at AS timestamp FROM evidence WHERE case_id=?", (case_id,)).fetchall()
        notes = conn.execute("SELECT id AS ref_id, substr(body,1,180) AS label, created_at AS timestamp FROM notes WHERE case_id=?", (case_id,)).fetchall()
        events = conn.execute("SELECT id AS ref_id, event AS label, created_at AS timestamp FROM audit WHERE case_id=?", (case_id,)).fetchall()
    items = ([{"type": "evidence", **dict(row)} for row in evidence] +
             [{"type": "note", **dict(row)} for row in notes] +
             [{"type": "audit", **dict(row)} for row in events])
    return sorted(items, key=lambda item: item["timestamp"])

@app.get("/api/cases/{case_id}/correlations")
def correlations(case_id: str):
    case_or_404(case_id)
    with connect() as conn:
        evidence = [dict(r) for r in conn.execute(
            "SELECT id,case_id,original_name,sha256,size_bytes,detected_mime,uploaded_at,tags FROM evidence WHERE case_id=? ORDER BY uploaded_at",
            (case_id,)).fetchall()]
    groups = {}
    for item in evidence:
        groups.setdefault(item["sha256"], []).append(item)
    duplicate_hashes = [{"sha256": digest, "items": items} for digest, items in groups.items() if len(items) > 1]
    return {"case_id": case_id, "evidence_count": len(evidence), "duplicate_hash_groups": duplicate_hashes,
            "same_name_groups": [{"name": name, "evidence_ids": [x["id"] for x in items]}
              for name, items in _group(evidence, "original_name").items() if len(items) > 1],
            "note": "These are deterministic metadata/hash correlations only; matching names do not prove a shared source."}

def _group(items, key):
    grouped = {}
    for item in items:
        grouped.setdefault(item[key], []).append(item)
    return grouped

@app.get("/api/cases/{case_id}/manifest.json")
def manifest(case_id: str):
    case = case_or_404(case_id)
    with connect() as conn:
        evidence = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()]
        notes = [dict(r) for r in conn.execute("SELECT * FROM notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
        events = [dict(r) for r in conn.execute("SELECT * FROM audit WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
    items = []
    for e in evidence:
        items.append({"evidence_id": e["id"], "original_name": e["original_name"], "sha256_at_intake": e["sha256"],
                      "size_bytes": e["size_bytes"], "detected_mime_hint": e["detected_mime"],
                      "uploaded_at": e["uploaded_at"], "tags": e["tags"], "source_description": e["source_description"],
                      "collected_by": e["collected_by"], "acquired_at": e["acquired_at"],
                      "custody": custody_for_manifest(e["id"]), "analysis": json.loads(e["analysis_json"])})
    document = {"schema_version": "1.0", "generated_at": now(), "case": case, "evidence": items,
                "notes": notes, "audit_events": events,
                "limitations": ["Manifest is not digitally signed.", "Hashes prove byte equality only against recorded values.",
                                "Audit chain is stored in the same mutable local database."]}
    audit(case_id, "manifest_generated", {"evidence_count": len(items)})
    return JSONResponse(document, headers={"Content-Disposition": f'attachment; filename="{case_id}-manifest.json"'})

def custody_for_manifest(evidence_id):
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()]

@app.get("/api/cases/{case_id}/report")
def report(case_id: str):
    case = case_or_404(case_id)
    with connect() as conn:
        evidence = [dict(row) for row in conn.execute(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()]
        notes = [dict(row) for row in conn.execute(
            "SELECT * FROM notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
        audit_events = [dict(row) for row in conn.execute(
            "SELECT * FROM audit WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
        for item in evidence:
            item["custody_events"] = [dict(row) for row in conn.execute(
                "SELECT * FROM custody WHERE evidence_id=? ORDER BY id", (item["id"],)).fetchall()]
    path = REPORT_DIR / (case_id + ".pdf")
    build_report(path, case, evidence, notes, audit_events)
    audit(case_id, "report_generated", {"filename": path.name})
    return FileResponse(path, media_type="application/pdf", filename=case_id + "-forensic-report.pdf")
