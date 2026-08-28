from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


def make_security_pdf(result, path):
    path=Path(path)
    styles=getSampleStyleSheet(); title=styles["Title"]; title.alignment=TA_CENTER
    story=[Paragraph("Smart Contract Security Report",title),Spacer(1,12)]
    story += [Paragraph(f"Network: {result.get('network','Unknown')}",styles['BodyText']),Paragraph(f"Address: {result.get('address','')}",styles['BodyText']),Paragraph(f"Verification: {'Verified' if result.get('verified') else 'Unverified'}",styles['BodyText']),Paragraph(f"Risk score: {result.get('risk_score',0)}/100 — {result.get('risk_label',result.get('risk',''))}",styles['BodyText']),Spacer(1,12)]
    rows=[["Severity","Type","Location","Finding"]]
    for f in result.get('findings',[]): rows.append([f.get('severity',''),f.get('type',''),f"{f.get('file','')}:{f.get('line','')}",f.get('message','')])
    if len(rows)==1: rows.append(["—","—","—","No heuristic findings detected"])
    table=Table(rows,colWidths=[55,105,120,220],repeatRows=1)
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#222222')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),0.4,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f5f5f5')])]))
    story += [table,Spacer(1,12),Paragraph(result.get('note','Automated heuristic analysis only; not a formal audit.'),styles['Italic'])]
    SimpleDocTemplate(str(path),pagesize=A4,rightMargin=30,leftMargin=30,topMargin=30,bottomMargin=30).build(story)
    return str(path)
