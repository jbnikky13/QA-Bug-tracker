"""
reports.py — generates official, submittable QA bug reports (PDF and DOCX)
from a scan result dict as produced by scanner.run_scan().

Expected bug dict fields (all optional except id/severity/type/page/message):
    id, severity, priority, type, page, message, evidence,
    wcag, selector, html_snippet, steps, expected, actual, help_url, screenshot
"""

from datetime import datetime
from pathlib import Path

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak, HRFlowable
)

SEVERITY_COLOR = {
    "Critical": "C00000",
    "High": "E36C09",
    "Medium": "BF8F00",
    "Low": "548235",
}
SEVERITY_COLOR_RGB = {
    "Critical": colors.HexColor("#C00000"),
    "High": colors.HexColor("#E36C09"),
    "Medium": colors.HexColor("#BF8F00"),
    "Low": colors.HexColor("#548235"),
}


def _summary_counts(bugs):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for b in bugs:
        counts[b.get("severity", "Low")] = counts.get(b.get("severity", "Low"), 0) + 1
    return counts


# ---------------------------------------------------------------- DOCX -----

def _set_cell_shading(cell, hex_color):
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    cell._tc.get_or_add_tcPr().append(shd)


def make_docx(result, out_path):
    doc = Document()

    # Base font
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)

    bugs = result["bugs"]
    pages = result["pages"]
    counts = _summary_counts(bugs)
    generated = datetime.now().strftime("%B %d, %Y %H:%M")

    # --- Cover page ---
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("QA / Accessibility Bug Report")
    run.font.size = Pt(28)
    run.font.bold = True

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sub.add_run(result.get("target", ""))
    run.font.size = Pt(14)
    run.font.color.rgb = RGBColor(0x44, 0x44, 0x44)

    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta.add_run(f"Generated: {generated}\nPages tested: {len(pages)}   |   Total findings: {len(bugs)}")

    doc.add_page_break()

    # --- Executive summary ---
    doc.add_heading("1. Executive Summary", level=1)
    doc.add_paragraph(
        f"This report documents the results of an automated QA scan of {result.get('target','the target site')}. "
        f"The scan covered {len(pages)} page(s) and identified {len(bugs)} finding(s) across functional, "
        f"visual, and accessibility categories. Findings are prioritized by severity to support triage."
    )

    sev_table = doc.add_table(rows=1, cols=2)
    sev_table.style = "Light Grid Accent 1"
    hdr = sev_table.rows[0].cells
    hdr[0].text, hdr[1].text = "Severity", "Count"
    for sev in ["Critical", "High", "Medium", "Low"]:
        row = sev_table.add_row().cells
        row[0].text = sev
        row[1].text = str(counts.get(sev, 0))
        _set_cell_shading(row[0], SEVERITY_COLOR[sev])
        row[0].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        row[0].paragraphs[0].runs[0].font.bold = True

    # --- Methodology ---
    doc.add_heading("2. Methodology", level=1)
    doc.add_paragraph(
        "Findings were produced by an automated scan using a headless Chromium browser (Playwright). "
        "The scan checked for: broken links and images, HTTP errors, JavaScript console errors and "
        "failed network requests, layout/rendering issues (viewport overflow, off-screen elements), "
        "and accessibility violations evaluated against WCAG 2.x success criteria via axe-core, "
        "supplemented by manual-style DOM checks (e.g. missing alt text)."
    )

    # --- Pages tested ---
    doc.add_heading("3. Pages Tested", level=1)
    pt = doc.add_table(rows=1, cols=2)
    pt.style = "Light List Accent 1"
    pt.rows[0].cells[0].text, pt.rows[0].cells[1].text = "URL", "HTTP Status"
    for pg in pages:
        row = pt.add_row().cells
        row[0].text = pg.get("url", "")
        row[1].text = str(pg.get("status", ""))

    doc.add_page_break()

    # --- Detailed findings ---
    doc.add_heading("4. Detailed Findings", level=1)

    if not bugs:
        doc.add_paragraph("No issues were detected during this scan.")

    for b in bugs:
        h = doc.add_heading(f'{b.get("id","")} — {b.get("type","")}', level=2)
        for run in h.runs:
            run.font.color.rgb = RGBColor.from_string(SEVERITY_COLOR.get(b.get("severity", "Low"), "000000"))

        info = doc.add_table(rows=0, cols=2)
        info.style = "Light Grid"
        info.alignment = WD_TABLE_ALIGNMENT.LEFT

        def add_row(label, value):
            row = info.add_row().cells
            row[0].text = label
            row[0].paragraphs[0].runs[0].font.bold = True
            row[1].text = str(value) if value else "N/A"

        add_row("Severity", b.get("severity"))
        add_row("Priority", b.get("priority"))
        add_row("Page / URL", b.get("page"))
        add_row("WCAG Reference", b.get("wcag"))
        add_row("Element Selector", b.get("selector"))
        if b.get("html_snippet"):
            add_row("HTML Snippet", b.get("html_snippet"))

        doc.add_paragraph()
        p = doc.add_paragraph()
        p.add_run("Description: ").bold = True
        p.add_run(b.get("message", ""))

        p = doc.add_paragraph()
        p.add_run("Steps to Reproduce:").bold = True
        for line in (b.get("steps") or "").split("\n"):
            if line.strip():
                doc.add_paragraph(line.strip(), style="List Number")

        p = doc.add_paragraph()
        p.add_run("Expected Result: ").bold = True
        p.add_run(b.get("expected", ""))

        p = doc.add_paragraph()
        p.add_run("Actual Result: ").bold = True
        p.add_run(b.get("actual", ""))

        if b.get("help_url"):
            p = doc.add_paragraph()
            p.add_run("Reference: ").bold = True
            p.add_run(b.get("help_url"))

        if b.get("screenshot") and Path(b["screenshot"]).exists():
            p = doc.add_paragraph()
            p.add_run("Evidence:").bold = True
            try:
                doc.add_picture(b["screenshot"], width=Inches(5.5))
            except Exception:
                pass

        doc.add_paragraph("_" * 90)

    doc.save(str(out_path))
    return str(out_path)


# ----------------------------------------------------------------- PDF -----

def make_pdf(result, out_path):
    bugs = result["bugs"]
    pages = result["pages"]
    counts = _summary_counts(bugs)
    generated = datetime.now().strftime("%B %d, %Y %H:%M")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleBig", parent=styles["Normal"], fontName="Helvetica-Bold",
                                  fontSize=26, leading=30, spaceAfter=6, alignment=1)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=13, textColor=colors.HexColor("#444444"),
                                alignment=1, spaceAfter=4)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], alignment=1, spaceAfter=2)
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], spaceBefore=14, spaceAfter=8)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=12, spaceAfter=4)
    body = styles["BodyText"]
    label = ParagraphStyle("Label", parent=body, fontName="Helvetica-Bold")

    doc = SimpleDocTemplate(str(out_path), pagesize=LETTER,
                             topMargin=0.9 * inch, bottomMargin=0.9 * inch,
                             leftMargin=0.9 * inch, rightMargin=0.9 * inch)
    story = []

    # Cover
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("QA / Accessibility Bug Report", title_style))
    story.append(Paragraph(result.get("target", ""), sub_style))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"Generated: {generated}", meta_style))
    story.append(Paragraph(f"Pages tested: {len(pages)} &nbsp;|&nbsp; Total findings: {len(bugs)}", meta_style))
    story.append(PageBreak())

    # Executive summary
    story.append(Paragraph("1. Executive Summary", h1))
    story.append(Paragraph(
        f"This report documents the results of an automated QA scan of {result.get('target','the target site')}. "
        f"The scan covered {len(pages)} page(s) and identified {len(bugs)} finding(s) across functional, "
        f"visual, and accessibility categories. Findings are prioritized by severity to support triage.",
        body))
    story.append(Spacer(1, 0.15 * inch))

    sev_data = [["Severity", "Count"]] + [[s, str(counts.get(s, 0))] for s in ["Critical", "High", "Medium", "Low"]]
    sev_table = Table(sev_data, colWidths=[2.5 * inch, 2.5 * inch])
    sev_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F2F2F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"], start=1):
        sev_style.append(("BACKGROUND", (0, i), (0, i), SEVERITY_COLOR_RGB[sev]))
        sev_style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)

    # Methodology
    story.append(Paragraph("2. Methodology", h1))
    story.append(Paragraph(
        "Findings were produced by an automated scan using a headless Chromium browser (Playwright). "
        "The scan checked for: broken links and images, HTTP errors, JavaScript console errors and "
        "failed network requests, layout/rendering issues (viewport overflow, off-screen elements), "
        "and accessibility violations evaluated against WCAG 2.x success criteria via axe-core, "
        "supplemented by manual-style DOM checks (e.g. missing alt text).", body))

    # Pages tested
    story.append(Paragraph("3. Pages Tested", h1))
    pt_data = [["URL", "HTTP Status"]] + [[p.get("url", ""), str(p.get("status", ""))] for p in pages]
    pt_table = Table(pt_data, colWidths=[4.8 * inch, 1.5 * inch])
    pt_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F2F2F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(pt_table)
    story.append(PageBreak())

    # Detailed findings
    story.append(Paragraph("4. Detailed Findings", h1))
    if not bugs:
        story.append(Paragraph("No issues were detected during this scan.", body))

    for b in bugs:
        sev = b.get("severity", "Low")
        heading_style = ParagraphStyle(f"H2_{sev}", parent=h2, textColor=SEVERITY_COLOR_RGB.get(sev, colors.black))
        story.append(Paragraph(f'{b.get("id","")} — {b.get("type","")}', heading_style))

        info_data = [
            ["Severity", b.get("severity", "")],
            ["Priority", b.get("priority", "")],
            ["Page / URL", b.get("page", "")],
            ["WCAG Reference", b.get("wcag", "N/A")],
            ["Element Selector", b.get("selector", "N/A")],
        ]
        info_table = Table(info_data, colWidths=[1.6 * inch, 4.7 * inch])
        info_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.08 * inch))

        story.append(Paragraph("<b>Description:</b> " + b.get("message", ""), body))
        story.append(Paragraph("<b>Steps to Reproduce:</b>", label))
        for line in (b.get("steps") or "").split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), body))
        story.append(Paragraph("<b>Expected Result:</b> " + b.get("expected", ""), body))
        story.append(Paragraph("<b>Actual Result:</b> " + b.get("actual", ""), body))
        if b.get("help_url"):
            story.append(Paragraph("<b>Reference:</b> " + b.get("help_url"), body))

        if b.get("screenshot") and Path(b["screenshot"]).exists():
            try:
                story.append(Spacer(1, 0.05 * inch))
                story.append(Image(b["screenshot"], width=5.2 * inch, height=3.0 * inch, kind="proportional"))
            except Exception:
                pass

        story.append(Spacer(1, 0.1 * inch))
        story.append(HRFlowable(width="100%", color=colors.lightgrey))
        story.append(Spacer(1, 0.1 * inch))

    doc.build(story)
    return str(out_path)
