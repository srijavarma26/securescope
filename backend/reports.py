"""
SecureScope — PDF Security Report Generator
Produces professional, exportable PDF security assessment reports using ReportLab.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

class NumberedCanvas(canvas.Canvas):
    """Adds page numbers and header/footer to each page."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "SecureScope — Web Application Security Assessment Report")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)

        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_text)
        self.drawString(54, 40, "CONFIDENTIAL — Authorized Security Evaluation Only")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 52, 558, 52)
        self.restoreState()

def generate_pdf_report(scan_data, vulnerabilities, report_type="Executive Security Report"):
    """
    Generates a PDF security report and returns the absolute file path.
    """
    scan_id = scan_data.get('scan_id', 'SCN-0000')
    filename = f"SecureScope_Report_{scan_id}.pdf"
    file_path = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom color palette matching SecureScope brand
    c_primary = colors.HexColor("#0f172a")  # Deep slate navy
    c_cyan = colors.HexColor("#0284c7")     # Cyan accent
    c_dark = colors.HexColor("#1e293b")
    c_muted = colors.HexColor("#475569")
    c_border = colors.HexColor("#e2e8f0")
    c_crit = colors.HexColor("#dc2626")
    c_high = colors.HexColor("#ea580c")
    c_med = colors.HexColor("#d97706")
    c_low = colors.HexColor("#059669")

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=c_cyan
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceAfter=8,
        spaceBefore=14
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=c_dark,
        spaceAfter=6,
        spaceBefore=10
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=c_dark
    )

    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=c_muted
    )

    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=c_primary
    )

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("SECURESCOPE", title_style))
    elements.append(Paragraph(f"{report_type} — Automated Security Assessment", subtitle_style))
    elements.append(Spacer(1, 12))
    elements.append(HRFlowable(width="100%", thickness=2, color=c_cyan, spaceBefore=4, spaceAfter=14))

    # 2. Assessment Metadata Table
    app_name = scan_data.get('app_name', 'Web Application')
    target_url = scan_data.get('target_url', 'N/A')
    scan_date = scan_data.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M'))
    risk_level = scan_data.get('risk_level', 'LOW')
    risk_score = scan_data.get('risk_score', 0)
    total_findings = scan_data.get('total_vulnerabilities', len(vulnerabilities))

    meta_data = [
        [
            Paragraph("Target Application:", meta_label), Paragraph(f"<b>{app_name}</b>", meta_val),
            Paragraph("Assessment Date:", meta_label), Paragraph(scan_date, meta_val)
        ],
        [
            Paragraph("Target URL:", meta_label), Paragraph(f"<code>{target_url}</code>", meta_val),
            Paragraph("Scan ID:", meta_label), Paragraph(f"<b>{scan_id}</b>", meta_val)
        ],
        [
            Paragraph("Overall Risk Level:", meta_label), Paragraph(f"<b>{risk_level}</b>", meta_val),
            Paragraph("Calculated Risk Score:", meta_label), Paragraph(f"<b>{risk_score} / 100</b>", meta_val)
        ]
    ]

    meta_table = Table(meta_data, colWidths=[110, 150, 110, 134])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 16))

    # 3. Executive Summary
    elements.append(Paragraph("1. Executive Summary", h1_style))
    summary_text = (
        f"SecureScope conducted an automated, non-destructive web application security analysis on target <b>{app_name}</b> "
        f"({target_url}). The assessment evaluated the target for Cross-Site Scripting (XSS), Injection indicators, "
        f"Access-Control issues, and missing security headers per OWASP guidelines. A total of <b>{total_findings}</b> security "
        f"findings were identified, resulting in a calculated risk score of <b>{risk_score}/100</b> (<b>{risk_level} RISK</b>). "
        "Immediate attention should be given to critical and high severity vulnerabilities to prevent unauthorized data access, "
        "session hijacking, or service compromise."
    )
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 14))

    # 4. Severity Distribution Breakdown
    elements.append(Paragraph("2. Vulnerability Severity Distribution", h1_style))
    crit_c = scan_data.get('critical_count', sum(1 for v in vulnerabilities if v.get('severity') == 'Critical'))
    high_c = scan_data.get('high_count', sum(1 for v in vulnerabilities if v.get('severity') == 'High'))
    med_c = scan_data.get('medium_count', sum(1 for v in vulnerabilities if v.get('severity') == 'Medium'))
    low_c = scan_data.get('low_count', sum(1 for v in vulnerabilities if v.get('severity') in ['Low', 'Informational']))

    dist_data = [
        ["Severity Level", "Count", "Percentage", "Impact Level"],
        ["Critical", str(crit_c), f"{(crit_c/max(1, total_findings))*100:.1f}%", "Severe System / Authentication Compromise"],
        ["High", str(high_c), f"{(high_c/max(1, total_findings))*100:.1f}%", "Significant Data or Session Hijacking Risk"],
        ["Medium", str(med_c), f"{(med_c/max(1, total_findings))*100:.1f}%", "Moderate Control Bypass / Defense-in-depth Gap"],
        ["Low / Informational", str(low_c), f"{(low_c/max(1, total_findings))*100:.1f}%", "Configuration Flaw / Server Information Disclosure"],
    ]

    dist_table = Table(dist_data, colWidths=[120, 60, 74, 250])
    dist_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (0, 1), colors.HexColor("#fee2e2")),
        ('TEXTCOLOR', (0, 1), (0, 1), c_crit),
        ('BACKGROUND', (0, 2), (0, 2), colors.HexColor("#ffedd5")),
        ('TEXTCOLOR', (0, 2), (0, 2), c_high),
        ('BACKGROUND', (0, 3), (0, 3), colors.HexColor("#fef3c7")),
        ('TEXTCOLOR', (0, 3), (0, 3), c_med),
        ('BACKGROUND', (0, 4), (0, 4), colors.HexColor("#d1fae5")),
        ('TEXTCOLOR', (0, 4), (0, 4), c_low),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border),
        ('TOPPADDING', (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(dist_table)
    elements.append(Spacer(1, 16))

    # 5. Detailed Vulnerability Findings
    elements.append(Paragraph("3. Detailed Vulnerability Findings", h1_style))
    if not vulnerabilities:
        elements.append(Paragraph("No vulnerabilities were identified during this assessment.", body_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            sev = vuln.get('severity', 'Medium')
            sev_color = c_crit if sev == 'Critical' else (c_high if sev == 'High' else (c_med if sev == 'Medium' else c_low))
            
            vuln_id = vuln.get('vuln_id', f'VUL-{idx:03d}')
            name = vuln.get('vuln_name', 'Security Finding')
            loc = vuln.get('affected_url', target_url)
            cat = vuln.get('category', 'Vulnerability')
            desc = vuln.get('description', '')
            impact = vuln.get('impact', '')
            remediation = vuln.get('remediation', [])
            if isinstance(remediation, str):
                remediation = [remediation]

            elements.append(Paragraph(f"<b>3.{idx} [{vuln_id}] {name}</b>", h2_style))
            
            detail_table_data = [
                [Paragraph("Severity:", meta_label), Paragraph(f"<b>{sev}</b>", ParagraphStyle('SevTxt', parent=body_style, textColor=sev_color, fontName='Helvetica-Bold')),
                 Paragraph("Category:", meta_label), Paragraph(cat, body_style)],
                [Paragraph("Affected URL:", meta_label), Paragraph(f"<code>{loc}</code>", body_style),
                 Paragraph("Confidence:", meta_label), Paragraph(vuln.get('confidence', 'High'), body_style)],
                [Paragraph("Description:", meta_label), Paragraph(desc, body_style), "", ""],
                [Paragraph("Impact:", meta_label), Paragraph(impact, body_style), "", ""]
            ]

            det_table = Table(detail_table_data, colWidths=[90, 264, 70, 80])
            det_table.setStyle(TableStyle([
                ('SPAN', (1, 2), (3, 2)),
                ('SPAN', (1, 3), (3, 3)),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ('BOX', (0, 0), (-1, -1), 0.5, c_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(det_table)
            elements.append(Spacer(1, 6))

            # Remediation items
            if remediation:
                elements.append(Paragraph("<b>Recommended Remediation:</b>", meta_label))
                for r in remediation:
                    elements.append(Paragraph(f"• {r}", ParagraphStyle('RemItem', parent=body_style, leftIndent=12, spaceAfter=2)))
            
            elements.append(Spacer(1, 10))

    # 6. Overall Remediation Strategy
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("4. Recommended Security Remediation Strategy", h1_style))
    recs = [
        "<b>Input Validation & Contextual Encoding:</b> Sanitize all user-controlled data against strict allow-lists and perform contextual HTML entity encoding to prevent XSS.",
        "<b>Parameterized Database Queries:</b> Ensure all data tier queries use prepared statements or ORM abstractions to eliminate injection vulnerabilities.",
        "<b>Enforce Defense-in-Depth HTTP Headers:</b> Deploy strict Content-Security-Policy (CSP), X-Frame-Options: SAMEORIGIN, and X-Content-Type-Options: nosniff headers.",
        "<b>Object-Level Authorization:</b> Implement rigorous session and ownership validation before returning records or performing state-changing actions.",
        "<b>Secure Cookie Configuration:</b> Set HttpOnly, Secure, and SameSite=Lax flags on all authentication and session tokens."
    ]
    for rec in recs:
        elements.append(Paragraph(f"• {rec}", ParagraphStyle('StratRec', parent=body_style, leftIndent=8, spaceAfter=4)))

    # Build document with NumberedCanvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    return file_path
