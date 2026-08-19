from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from docx import Document
from pathlib import Path

def make_pdf(result, path):
    styles=getSampleStyleSheet()
    doc=SimpleDocTemplate(str(path), pagesize=A4)
    story=[Paragraph("QA Bug Tracker — Test Report", styles["Title"]),
           Paragraph(f"Target: {result['target']}", styles["Normal"]),
           Spacer(1,12)]
    story.append(Paragraph(f"Pages tested: {len(result['pages'])} | Issues: {len(result['bugs'])} | Passed checks: {result['passed']}", styles["Normal"]))
    story.append(Spacer(1,12))
    for b in result["bugs"]:
        story += [Paragraph(f"{b['id']} — {b['severity']} — {b['type']}", styles["Heading2"]),
                  Paragraph(f"Page: {b['page']}", styles["Normal"]),
                  Paragraph(f"Message: {b['message']}", styles["Normal"]),
                  Paragraph(f"Evidence: {b.get('evidence','')}", styles["Normal"]), Spacer(1,8)]
        for p in result["pages"]:
            if p["url"] == b["page"] and p.get("screenshot") and Path(p["screenshot"]).exists():
                story.append(Image(p["screenshot"], width=450, height=280))
                story.append(Spacer(1,8))
                break
    doc.build(story)
    return path

def make_docx(result, path):
    doc=Document()
    doc.add_heading("QA Bug Tracker — Test Report", 0)
    doc.add_paragraph(f"Target: {result['target']}")
    doc.add_paragraph(f"Pages tested: {len(result['pages'])} | Issues: {len(result['bugs'])} | Passed checks: {result['passed']}")
    for b in result["bugs"]:
        doc.add_heading(f"{b['id']} — {b['severity']} — {b['type']}", level=1)
        doc.add_paragraph(f"Page: {b['page']}")
        doc.add_paragraph(f"Message: {b['message']}")
        doc.add_paragraph(f"Evidence: {b.get('evidence','')}")
        for p in result["pages"]:
            if p["url"] == b["page"] and p.get("screenshot") and Path(p["screenshot"]).exists():
                doc.add_picture(p["screenshot"], width=None)
                break
    doc.save(path)
    return path
