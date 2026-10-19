import json
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

def safe(value):
    return escape(str(value if value is not None else ""))

def build_report(path, case, evidence, notes, audit_events=None):
    styles = getSampleStyleSheet()
    story = [
        Paragraph("OmniForensics AI — Case Report", styles["Title"]),
        Paragraph("Case ID: " + safe(case["id"]), styles["Normal"]),
        Paragraph("Title: " + safe(case["title"]), styles["Normal"]),
        Paragraph("Description: " + safe(case.get("description", "")), styles["Normal"]),
        Paragraph("Created: " + safe(case["created_at"]), styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph("This report summarizes automated observations from files supplied to this prototype. It is not a legal conclusion, proof of a crime, or a certified forensic examination. Validate findings independently. File signatures and AI predictions can be incomplete or wrong.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Evidence inventory, provenance and analysis", styles["Heading2"])
    ]
    for item in evidence:
        story.extend([
            Paragraph(safe(item["original_name"]) + " — " + safe(item["id"]), styles["Heading3"]),
            Paragraph("SHA-256: " + safe(item["sha256"]), styles["Code"]),
            Paragraph("Size: " + str(item["size_bytes"]) + " bytes · MIME hint: " + safe(item["detected_mime"]), styles["Normal"]),
            Paragraph("Tags: " + safe(item.get("tags", "")) + " · Collected by: " + safe(item.get("collected_by", "")), styles["Normal"]),
            Paragraph("Source/acquisition notes: " + safe(item.get("source_description", "")), styles["Normal"]),
            Paragraph("Acquired at: " + safe(item.get("acquired_at", "")), styles["Normal"])
        ])
        custody = item.get("custody_events", [])
        story.append(Paragraph("Chain-of-custody records", styles["Heading4"]))
        if not custody:
            story.append(Paragraph("No custody records entered.", styles["Normal"]))
        for record in custody:
            line = " | ".join(str(record.get(k, "")) for k in ("created_at", "action", "handler", "location", "details", "audit_event_hash"))
            story.append(Paragraph(safe(line[:1200]), styles["BodyText"]))
        try:
            analysis = json.dumps(json.loads(item["analysis_json"]), indent=2, ensure_ascii=False)[:5000]
            story.append(Paragraph("Automated analysis metadata", styles["Heading4"]))
            story.append(Preformatted(analysis, styles["Code"]))
        except Exception:
            story.append(Paragraph("Analysis metadata could not be rendered.", styles["Italic"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph("Investigator notes", styles["Heading2"]))
    if not notes:
        story.append(Paragraph("No notes recorded.", styles["Normal"]))
    for note in notes:
        story.append(Paragraph(safe(note["created_at"]) + ": " + safe(note["body"][:1500]), styles["BodyText"]))
    story.append(Paragraph("Audit events", styles["Heading2"]))
    if not audit_events:
        story.append(Paragraph("No audit events recorded.", styles["Normal"]))
    for event in (audit_events or []):
        line = f'{event.get("created_at", "")} | {event.get("event", "")} | {event.get("event_hash") or "legacy/unhashed"}'
        story.append(Paragraph(safe(line), styles["Code"]))
    story.extend([
        Spacer(1, 10),
        Paragraph("SHA-256 identifies file bytes; it does not prove who created a file or whether its contents are truthful.", styles["Italic"]),
        Paragraph("Audit hash chaining provides tamper evidence, not an immutable or externally trusted log. This PDF is not digitally signed.", styles["Italic"])
    ])
    SimpleDocTemplate(str(path), pagesize=letter, leftMargin=.55*inch, rightMargin=.55*inch).build(story)
