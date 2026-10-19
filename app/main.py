import base64
import hashlib
import io
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from PIL import Image, ExifTags
from pypdf import PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted

MAX_FILE_BYTES = int(os.getenv("OMNIFORENSICS_MAX_FILE_MB", "4")) * 1024 * 1024
MAX_FILES = 5
app = FastAPI(title="OmniForensics AI — Stateless Scene Analysis", version="1.0.0")
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
origins = [x.strip().rstrip("/") for x in os.getenv("OMNIFORENSICS_CORS_ORIGINS", "https://codex-inn.github.io,http://localhost:8000,http://127.0.0.1:8000").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET","POST","OPTIONS"], allow_headers=["Content-Type","Authorization"], max_age=600)

def secure(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store, max-age=0")
    response.headers.setdefault("Pragma", "no-cache")
    return response

@app.middleware("http")
async def security(request: Request, call_next):
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > MAX_FILE_BYTES * MAX_FILES * 2 + 2_000_000:
                return secure(JSONResponse({"detail":"Request too large"}, status_code=413))
        except ValueError:
            return secure(JSONResponse({"detail":"Invalid Content-Length"}, status_code=400))
    if request.method != "OPTIONS" and os.getenv("OMNIFORENSICS_PUBLIC_MODE","false").lower() == "true" and request.url.path != "/api/health":
        username, password = os.getenv("OMNIFORENSICS_USERNAME",""), os.getenv("OMNIFORENSICS_PASSWORD","")
        if not username or not password:
            return secure(JSONResponse({"detail":"Backend access is not configured"}, status_code=503))
        user = pwd = ""
        header = request.headers.get("authorization","")
        if header.startswith("Basic "):
            try:
                user, pwd = base64.b64decode(header[6:], validate=True).decode().split(":",1)
            except (ValueError, UnicodeDecodeError):
                pass
        if not (secrets.compare_digest(user,username) and secrets.compare_digest(pwd,password)):
            return secure(Response("Authentication required",status_code=401,headers={"WWW-Authenticate":'Basic realm="OmniForensics AI", charset="UTF-8"'}))
    return secure(await call_next(request))

@app.get("/", response_class=HTMLResponse)
def home():
    # The Pages edition uses relative asset paths; the optional API serves those assets under /static.
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    return html.replace('href="styles.css"', 'href="/static/styles.css"').replace('src="app.js"', 'src="/static/app.js"')

@app.get("/api/health")
def health():
    return {"status":"ok","mode":"stateless","version":"1.0.0","persistent_case_storage":False,"max_file_bytes":MAX_FILE_BYTES,"max_files_per_request":MAX_FILES}

class FileInput(BaseModel):
    filename: str = Field(min_length=1, max_length=180)
    content_base64: str = Field(min_length=1)

class SceneInput(BaseModel):
    case_reference: str = Field(default="", max_length=160)
    incident_date: str = Field(default="", max_length=100)
    location: str = Field(default="", max_length=300)
    incident_type: str = Field(default="Unspecified", max_length=120)
    description: str = Field(default="", max_length=12000)
    observations: str = Field(default="", max_length=12000)
    files: list[FileInput] = Field(default_factory=list, max_length=MAX_FILES)

def analyze_file(item: FileInput):
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", Path(item.filename).name)[:180] or "uploaded-file"
    try:
        raw = base64.b64decode(item.content_base64, validate=True)
    except Exception:
        raise HTTPException(422, "Invalid base64 file data")
    if not raw:
        raise HTTPException(422, name + " is empty")
    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(413, name + " exceeds the per-file size limit")
    digest = hashlib.sha256(raw).hexdigest()
    markers = [(b"\x89PNG\r\n\x1a\n","PNG image"),(b"\xff\xd8\xff","JPEG image"),(b"GIF87a","GIF image"),(b"GIF89a","GIF image"),(b"%PDF-","PDF document"),(b"PK\x03\x04","ZIP-based file"),(b"\x7fELF","ELF executable"),(b"MZ","Windows executable"),(b"OggS","Ogg media"),(b"RIFF","RIFF container")]
    result = {"filename":name,"size_bytes":len(raw),"sha256":digest,"signature_hint":next((label for mark,label in markers if raw.startswith(mark)),"Unknown / unrecognized signature")}
    if raw.startswith((b"\x89PNG\r\n\x1a\n",b"\xff\xd8\xff",b"GIF87a",b"GIF89a",b"BM")):
        try:
            with Image.open(io.BytesIO(raw)) as im:
                result["image"]={"format":im.format,"width":im.width,"height":im.height,"mode":im.mode}
                exif={}
                for key,val in im.getexif().items():
                    label=ExifTags.TAGS.get(key,str(key))
                    if isinstance(val,(str,int,float,bool)): exif[label]=val
                    if len(exif)>=25: break
                if exif: result["image"]["exif"]=exif
        except Exception:
            result["image_parse_note"]="Image-like bytes could not be parsed."
    if raw.startswith(b"%PDF-") or Path(name).suffix.lower()==".pdf":
        try:
            pdf=PdfReader(io.BytesIO(raw),strict=False)
            meta=pdf.metadata or {}
            result["pdf"]={"page_count":len(pdf.pages),"metadata":{str(k).lstrip("/"):str(v)[:400] for k,v in meta.items() if v is not None and str(k).lstrip("/") in {"Title","Author","Creator","Producer","CreationDate","ModDate"}}}
        except Exception:
            result["pdf_parse_note"]="PDF metadata could not be parsed."
    result["limitation"]="Metadata/signature hints do not establish authenticity, origin, identity, timeline, or criminal activity."
    return result

def build_analysis(data: SceneInput):
    if len(data.files)>MAX_FILES: raise HTTPException(413,"Too many files")
    files=[analyze_file(item) for item in data.files]
    checks=[]
    if not data.description.strip(): checks.append("Incident description was not supplied.")
    if not data.observations.strip(): checks.append("No investigator observations were supplied.")
    if not data.incident_date.strip(): checks.append("Incident date/time is unspecified; verify against a trusted source.")
    if not data.location.strip(): checks.append("Scene location is unspecified.")
    if not files: checks.append("No files were submitted for metadata and hash review.")
    seen={}
    for item in files: seen.setdefault(item["sha256"],[]).append(item["filename"])
    for names in seen.values():
        if len(names)>1: checks.append("Identical file bytes detected among submitted files: "+", ".join(names))
    unknown=[f["filename"] for f in files if f["signature_hint"].startswith("Unknown")]
    if unknown: checks.append("No recognized leading-byte signature detected for: "+", ".join(unknown))
    return {"product":"OmniForensics AI — Stateless Crime Scene Analysis","generated_at_utc":datetime.now(timezone.utc).isoformat(),"case_reference":data.case_reference.strip(),"incident_date":data.incident_date.strip(),"location":data.location.strip(),"incident_type":data.incident_type.strip(),"description":data.description.strip(),"investigator_observations":[x.strip(" •\t-") for x in data.observations.splitlines() if x.strip()],"automated_checks_and_followups":checks,"files":files,"file_count":len(files),"privacy":{"persistent_case_storage":False,"files_written_by_application":False,"database_used":False,"retention":"Request processing only; response returned to client."},"scope_note":"Educational triage only. This report does not determine that a crime occurred, identify suspects, establish cause of death, reconstruct events, or prove guilt. Human investigators must independently verify findings."}

@app.post("/api/analyze")
def analyze(data: SceneInput):
    return build_analysis(data)

@app.post("/api/report/pdf")
def pdf_report(data: SceneInput):
    report=build_analysis(data)
    buffer=io.BytesIO()
    doc=SimpleDocTemplate(buffer,pagesize=letter,rightMargin=0.65*inch,leftMargin=0.65*inch,topMargin=0.6*inch,bottomMargin=0.6*inch,title="OmniForensics AI Analysis Report")
    styles=getSampleStyleSheet()
    story=[Paragraph("OmniForensics AI",styles["Title"]),Paragraph("Crime Scene Analysis & Triage Report",styles["Heading1"]),Paragraph("Generated UTC: "+escape(report["generated_at_utc"]),styles["Normal"]),Spacer(1,10)]
    for label,key in [("Case reference","case_reference"),("Incident date/time","incident_date"),("Location","location"),("Incident type","incident_type"),("Description","description")]:
        story.extend([Paragraph(escape(label),styles["Heading3"]),Paragraph(escape(report[key] or "Not supplied").replace("\n","<br/>"),styles["BodyText"])])
    story.append(Paragraph("Investigator observations",styles["Heading2"]))
    for item in report["investigator_observations"] or ["No observations supplied."]: story.append(Paragraph("• "+escape(item),styles["BodyText"]))
    story.append(Paragraph("File triage and SHA-256",styles["Heading2"]))
    for item in report["files"]:
        story.extend([Paragraph(escape(item["filename"]),styles["Heading3"]),Paragraph("SHA-256: "+item["sha256"],styles["Code"]),Paragraph("Size: "+str(item["size_bytes"])+" bytes · Signature hint: "+escape(item["signature_hint"]),styles["BodyText"])])
        if item.get("image"):
            im=item["image"]; story.append(Paragraph("Image: "+escape(str(im["format"]))+" · "+str(im["width"])+" × "+str(im["height"]),styles["BodyText"]))
            if im.get("exif"): story.append(Preformatted(json.dumps(im["exif"],indent=2,ensure_ascii=False)[:2000],styles["Code"]))
        if item.get("pdf"):
            story.append(Paragraph("PDF page count: "+str(item["pdf"]["page_count"]),styles["BodyText"]))
            if item["pdf"].get("metadata"): story.append(Preformatted(json.dumps(item["pdf"]["metadata"],indent=2,ensure_ascii=False)[:2000],styles["Code"]))
    if not report["files"]: story.append(Paragraph("No files submitted.",styles["BodyText"]))
    story.append(Paragraph("Checks and follow-up items",styles["Heading2"]))
    for item in report["automated_checks_and_followups"] or ["No automated flags generated. This does not prove no issues exist."]: story.append(Paragraph("• "+escape(item),styles["BodyText"]))
    story.extend([Spacer(1,10),Paragraph("Scope and data handling",styles["Heading2"]),Paragraph(escape(report["scope_note"]),styles["BodyText"]),Paragraph("The application does not intentionally save requests, uploads, cases, or reports to backend storage. Hosting infrastructure may still collect operational metadata/logs; the browser and downloaded report may retain a copy. Review host privacy terms before submitting sensitive data.",styles["BodyText"])])
    doc.build(story)
    pdf=buffer.getvalue()
    buffer.close()
    return Response(pdf,media_type="application/pdf",headers={"Content-Disposition":'attachment; filename="omniforensics-analysis-report.pdf"',"Cache-Control":"no-store, max-age=0"})
