"""
Module 7: Forensic Report Generation (PS Section 5)

Generates a structured PDF report for one case, suitable for institutional
action, legal review, cyber incident response, and law enforcement handoff.

Includes:
- Case summary and fraud score
- Full authentication analysis
- Origin trace and geolocation
- BEC/NLP signal breakdown
- Evidence integrity (SHA-256 hash of the original raw email)
- Chain-of-custody log (who/what touched this case, when)

Can optionally mask PII (Section 6 — privacy/compliance safeguard) for
reports that need to be shared more broadly before full legal review.
"""

import os
import sys
import io
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

sys.path.insert(0, os.path.dirname(__file__))
from db import Case, AccessLog, get_session
from privacy import mask_email_address, mask_ip_address


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=20, leading=24, spaceAfter=4,
        textColor=colors.HexColor("#1a1a1a"), fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=10, textColor=colors.HexColor("#666666"),
        spaceAfter=16, fontName="Helvetica"
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontSize=13, spaceBefore=16, spaceAfter=8,
        textColor=colors.HexColor("#1a1a1a"), fontName="Helvetica-Bold"
    ))
    styles.add(ParagraphStyle(
        name="BodyTextSmall", fontSize=9.5, leading=14, fontName="Helvetica"
    ))
    styles.add(ParagraphStyle(
        name="MonoSmall", fontSize=8.5, leading=12, fontName="Courier"
    ))
    return styles


def _risk_color(risk_level):
    return {
        "CRITICAL": colors.HexColor("#E5484D"),
        "HIGH": colors.HexColor("#F2994A"),
        "MEDIUM": colors.HexColor("#B8960C"),
        "LOW": colors.HexColor("#2E9E5B"),
    }.get(risk_level, colors.grey)


def generate_forensic_report(case_id: str, output_path: str, mask_pii: bool = False) -> str:
    """
    Builds a PDF forensic report for one case and writes it to output_path.
    Set mask_pii=True to redact victim/recipient email addresses and full IPs
    for wider distribution before formal legal review (Section 6 requirement).
    """
    db = get_session()
    try:
        case = db.query(Case).filter(Case.case_id == case_id).first()
        if not case:
            raise ValueError(f"Case {case_id} not found")

        audit_logs = db.query(AccessLog).filter(AccessLog.case_id == case_id).order_by(AccessLog.timestamp).all()

        # Log that a report was generated — chain of custody
        db.add(AccessLog(case_id=case_id, action="exported_report"))
        db.commit()

        styles = _build_styles()
        doc = SimpleDocTemplate(
            output_path, pagesize=letter,
            topMargin=0.7 * inch, bottomMargin=0.7 * inch,
            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        )
        story = []

        # --- Header ---
        story.append(Paragraph("TRACEBACK Forensic Intelligence Report", styles["ReportTitle"]))
        story.append(Paragraph(
            f"Case {case.case_id} &nbsp;|&nbsp; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            + (" &nbsp;|&nbsp; <b>PII MASKED VERSION</b>" if mask_pii else ""),
            styles["ReportSubtitle"]
        ))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
        story.append(Spacer(1, 10))

        # --- Verdict banner ---
        verdict_table = Table(
            [[Paragraph(f"<b>FRAUD SCORE: {case.final_score}/100</b>", styles["BodyTextSmall"]),
              Paragraph(f"<b>RISK LEVEL: {case.risk_level}</b>", styles["BodyTextSmall"])]],
            colWidths=[3 * inch, 3 * inch]
        )
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _risk_color(case.risk_level)),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 16))

        # --- Message summary ---
        story.append(Paragraph("1. Message Summary", styles["SectionHeading"]))
        from_addr = mask_email_address(case.from_address) if mask_pii else case.from_address
        summary_rows = [
            ["Subject", case.subject or "(none)"],
            ["From", from_addr or "(unknown)"],
            ["Reply-To domain", case.reply_to_domain or "(none)"],
            ["Received at", case.received_at.strftime("%Y-%m-%d %H:%M UTC") if case.received_at else "—"],
            ["Ingestion source", case.source or "—"],
        ]
        summary_table = Table(summary_rows, colWidths=[1.6 * inch, 4.4 * inch])
        summary_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)

        # --- Authentication ---
        story.append(Paragraph("2. Authentication & Protocol Analysis", styles["SectionHeading"]))
        auth_rows = [
            ["Check", "Result"],
            ["SPF", (case.spf or "unknown").upper()],
            ["DKIM", (case.dkim or "unknown").upper()],
            ["DMARC", (case.dmarc or "unknown").upper()],
            ["DMARC Policy", (case.dmarc_policy or "none").upper()],
        ]
        auth_table = Table(auth_rows, colWidths=[2 * inch, 4 * inch])
        auth_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(auth_table)

        # --- Origin trace ---
        story.append(Paragraph("3. Origin Traceability & Geolocation", styles["SectionHeading"]))
        origin_ip = mask_ip_address(case.originating_ip) if mask_pii else case.originating_ip
        geo_rows = [
            ["Originating IP", origin_ip or "(not extractable)"],
            ["Country", case.geo_country or "(unavailable)"],
            ["Region", case.geo_region or "(unavailable)"],
            ["City", case.geo_city or "(unavailable)"],
            ["ISP / Organization", case.geo_isp or "(unavailable)"],
            ["VPN / Proxy detected", "Yes" if case.is_proxy else "No"],
            ["Hosting / cloud infrastructure", "Yes" if case.is_hosting else "No"],
            ["Sender domain age", f"{case.domain_age_days} days" if case.domain_age_days is not None else "(unavailable)"],
        ]
        geo_table = Table(geo_rows, colWidths=[2.2 * inch, 3.8 * inch])
        geo_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(geo_table)

        # --- BEC / NLP signals ---
        story.append(Paragraph("4. Fraud Detection Signals", styles["SectionHeading"]))
        story.append(Paragraph(f"ML classifier fraud probability: <b>{round((case.ml_probability or 0)*100, 1)}%</b>", styles["BodyTextSmall"]))
        story.append(Paragraph(f"BEC rule-based score: <b>{case.bec_score or 0}/100</b>", styles["BodyTextSmall"]))
        if case.bec_categories:
            story.append(Paragraph(f"Categories triggered: {', '.join(case.bec_categories)}", styles["BodyTextSmall"]))
        if case.lookalike_domain:
            ld = case.lookalike_domain
            story.append(Paragraph(
                f"Lookalike domain detected: sender domain resembles <b>{ld.get('resembles')}</b> "
                f"({round(ld.get('similarity', 0) * 100)}% similarity)",
                styles["BodyTextSmall"]
            ))
        story.append(Spacer(1, 6))
        story.append(Paragraph("Full explanation:", styles["BodyTextSmall"]))
        for line in (case.explanation or []):
            story.append(Paragraph(f"&bull; {line}", styles["BodyTextSmall"]))

        # --- Evidence integrity ---
        story.append(Paragraph("5. Evidence Integrity", styles["SectionHeading"]))
        story.append(Paragraph(
            "The original raw email was hashed (SHA-256) at the time of analysis. "
            "This hash can be used to verify the evidence has not been altered since collection.",
            styles["BodyTextSmall"]
        ))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"SHA-256: {case.raw_email_hash}", styles["MonoSmall"]))

        # --- Chain of custody ---
        story.append(Paragraph("6. Chain of Custody", styles["SectionHeading"]))
        if audit_logs:
            custody_rows = [["Action", "Timestamp (UTC)"]] + [
                [log.action, log.timestamp.strftime("%Y-%m-%d %H:%M:%S")] for log in audit_logs
            ]
            custody_table = Table(custody_rows, colWidths=[3 * inch, 3 * inch])
            custody_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(custody_table)
        else:
            story.append(Paragraph("No prior access recorded before this export.", styles["BodyTextSmall"]))

        # --- Footer disclaimer ---
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "This report was generated automatically by the TRACEBACK platform. "
            "Findings are confidence-based assessments derived from header forensics, "
            "IP/domain intelligence, and machine learning classification, and should be "
            "corroborated by a qualified analyst before use in legal proceedings.",
            ParagraphStyle(name="Disclaimer", fontSize=8, textColor=colors.HexColor("#888888"), leading=11)
        ))

        doc.build(story)
        return output_path
    finally:
        db.close()


if __name__ == "__main__":
    # Test against whatever case exists in the local test DB
    db = get_session()
    case = db.query(Case).first()
    db.close()

    if not case:
        print("No cases in local DB — run pipeline.py first to seed test data.")
    else:
        out_path = f"/tmp/forensic_report_{case.case_id}.pdf"
        generate_forensic_report(case.case_id, out_path, mask_pii=False)
        print(f"Generated: {out_path}")

        masked_path = f"/tmp/forensic_report_{case.case_id}_masked.pdf"
        generate_forensic_report(case.case_id, masked_path, mask_pii=True)
        print(f"Generated (masked): {masked_path}")
