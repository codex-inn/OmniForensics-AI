import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

def build_report(path, case, evidence, notes):
    styles = getSampleStyleSheet()
    story = [
        Paragraph("OmniForensics AI — Case Report", styles["Title"]),
        Paragraph("Case ID: " + case["id"], styles["Normal"]),
        Paragraph("Title: " + case["title"], styles["Normal"]),
        Paragraph("Created: " + case["created_at"], styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph(
            "This report summarizes automated observations from files supplied to this prototype. "
            "It is not a legal conclusion, proof of a crime, or a certified forensic examination. "
            "Validate findings independently.", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Evidence inventory and analysis", styles["Heading2"])
    ]
    for item in evidence:
        story.extend([
            Paragraph(item["original_name"] + " — " + item["id"], styles["Heading3"]),
            Paragraph("SHA-256: " + item["sha256"], styles["Code"]),
            Paragraph("Size: " + str(item["size_bytes"]) + " bytes · MIME: " + item["detected_mime"], styles["Normal"])
        ])
        try:
            analysis = json.dumps(json.loads(item["analysis_json"]), indent=2, ensure_ascii=False)[:5000]
            story.append(Preformatted(analysis, styles["Code"]))
        except Exception:
            pass
        story.append(Spacer(1, 8))
    story.append(Paragraph("Investigator notes", styles["Heading2"]))
    for note in notes:
        story.append(Paragraph(note["created_at"] + ": " + note["body"][:1500], styles["BodyText"]))
    story.extend([
        Spacer(1, 10),
        Paragraph("SHA-256 identifies file bytes; it does not prove who created a file or whether its contents are truthful.", styles["Italic"])
    ])
    SimpleDocTemplate(str(path), pagesize=letter, leftMargin=.55*inch, rightMargin=.55*inch).build(story)
