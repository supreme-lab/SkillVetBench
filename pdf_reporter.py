"""
pdf_reporter.py
===============
Generates a professional PDF security report for each SkillReport.

Reports are stored in model-wise directories:
  <output_dir>/<model_name>/<skill_name>_security_report.pdf

Layout per report
─────────────────
  Page 1 — Cover: skill name, overall risk badge, CVSS score, timestamp
  Page 2 — Executive Summary + Skill Purpose + CVSS v3.1 metric table
  Page N — One section per vulnerability:
              • Finding header (ID, title, severity badge)
              • Affected content (monospace quote block)
              • Why it is dangerous
              • Step-by-step attack scenario
              • Remediation
  Last page — Dangerous patterns / Safe practices / Remediation priority

Usage
─────
  from pdf_reporter import PDFReporter
  reporter = PDFReporter(output_dir="reports", model_name="Qwen/Qwen2.5-14B-Instruct")
  path = reporter.save(report)          # returns Path to the saved PDF
  paths = reporter.save_batch(reports)  # list of Paths
"""

import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ── ReportLab imports ─────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes  import A4
    from reportlab.lib.units      import mm
    from reportlab.lib.colors     import (
        HexColor, white, black, Color
    )
    from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums      import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus       import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.platypus.flowables import Flowable
    from reportlab.pdfbase         import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
except ImportError:
    raise ImportError(
        "reportlab is required for PDF generation.\n"
        "  pip install reportlab"
    )

# ── Colour palette ────────────────────────────────────────────────────────────
DARK_BG      = HexColor("#0F1117")
CARD_BG      = HexColor("#1A1D27")
ACCENT_BLUE  = HexColor("#4A9EFF")
ACCENT_TEAL  = HexColor("#2DD4BF")

SEV_COLORS = {
    "CRITICAL": HexColor("#EF4444"),
    "HIGH":     HexColor("#F97316"),
    "MEDIUM":   HexColor("#EAB308"),
    "LOW":      HexColor("#22C55E"),
    "INFO":     HexColor("#94A3B8"),
    "NONE":     HexColor("#22C55E"),
    "UNKNOWN":  HexColor("#64748B"),
    "ERROR":    HexColor("#A855F7"),
}

SEV_BG = {
    "CRITICAL": HexColor("#3B0A0A"),
    "HIGH":     HexColor("#431407"),
    "MEDIUM":   HexColor("#3D2E00"),
    "LOW":      HexColor("#052E16"),
    "INFO":     HexColor("#1E293B"),
    "NONE":     HexColor("#052E16"),
    "UNKNOWN":  HexColor("#1E293B"),
}

TEXT_PRIMARY   = HexColor("#F1F5F9")
TEXT_SECONDARY = HexColor("#94A3B8")
TEXT_MUTED     = HexColor("#64748B")
BORDER_COLOR   = HexColor("#2D3748")
CODE_BG        = HexColor("#161B22")


def _sanitize(text: str) -> str:
    """Escape XML special chars for ReportLab Paragraph and strip null bytes."""
    if not text:
        return ""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\x00", "")
    return text


def _score_bar(score: float, color: Color, width_pts: float = 120) -> Table:
    """Render a horizontal progress bar as a 1-row Table."""
    filled = min(max(score / 10.0, 0.0), 1.0)
    bar_filled = width_pts * filled
    bar_empty  = width_pts * (1.0 - filled)
    data = [["", ""]]
    t = Table(data, colWidths=[bar_filled, bar_empty], rowHeights=[8])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, 0), color),
        ("BACKGROUND",  (1, 0), (1, 0), BORDER_COLOR),
        ("TOPPADDING",  (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING",(0,0), (-1, -1), 0),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",(0, 0), (-1, -1), 0),
    ]))
    return t


class PDFReporter:
    """
    Generates per-skill PDF security reports stored in model-named subdirectories.

    Directory layout:
        <output_dir>/
          <model_slug>/
            <skill_name>_security_report_<timestamp>.pdf
    """

    PAGE_W, PAGE_H = A4
    MARGIN         = 18 * mm

    def __init__(
        self,
        output_dir:  str  = "reports",
        model_name:  str  = "unknown_model",
    ):
        self.output_dir = Path(output_dir)
        self.model_name = model_name
        # Slugify model name for use as directory name
        # e.g. "Qwen/Qwen2.5-14B-Instruct" → "Qwen_Qwen2.5-14B-Instruct"
        self.model_slug = re.sub(r"[/\\:*?\"<>|]", "_", model_name)

    # ── Public interface ──────────────────────────────────────────────────────

    def save(self, report) -> Path:
        """Generate and save a PDF for a single SkillReport. Returns the Path."""
        out_dir = self.output_dir / self.model_slug
        out_dir.mkdir(parents=True, exist_ok=True)

        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug      = re.sub(r"[^\w\-.]", "_", Path(report.filename).stem)
        out_path  = out_dir / f"{slug}_security_report_{ts}.pdf"

        self._build_pdf(report, out_path)
        return out_path

    def save_batch(self, reports: list) -> List[Path]:
        """Generate PDFs for a list of SkillReports. Returns list of Paths."""
        paths = []
        for r in reports:
            paths.append(self.save(r))
        return paths

    # ── PDF construction ──────────────────────────────────────────────────────

    def _build_pdf(self, r, path: Path):
        doc = SimpleDocTemplate(
            str(path),
            pagesize    = A4,
            leftMargin  = self.MARGIN,
            rightMargin = self.MARGIN,
            topMargin   = self.MARGIN,
            bottomMargin= self.MARGIN,
            title       = f"Security Report — {r.skill_name}",
            author      = f"Skill Security Evaluator | Model: {self.model_name}",
            subject     = f"CVSS {r.cvss_base_score} {r.cvss_severity}",
        )

        styles = self._make_styles()
        story  = []

        # ── Cover page ────────────────────────────────────────────────
        story += self._cover(r, styles)
        story.append(PageBreak())

        # ── Summary + CVSS table ──────────────────────────────────────
        story += self._summary_section(r, styles)
        story.append(PageBreak())

        # ── Vulnerability sections ────────────────────────────────────
        if r.vulnerabilities:
            story.append(Paragraph("Vulnerability Findings", styles["SectionTitle"]))
            story.append(Spacer(1, 4 * mm))
            for v in r.vulnerabilities:
                story += self._vuln_section(v, styles)
        else:
            story.append(Paragraph("No Vulnerabilities Found", styles["SectionTitle"]))
            story.append(Spacer(1, 4 * mm))
            story.append(Paragraph(
                "This skill file passed all 12 security checks with no vulnerabilities detected.",
                styles["BodyText"]
            ))

        story.append(PageBreak())

        # ── Patterns + remediation priority ──────────────────────────
        story += self._patterns_section(r, styles)

        # ── Footer note ───────────────────────────────────────────────
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"Generated by Skill Security Evaluator &nbsp;|&nbsp; "
            f"Model: <font color='#{ACCENT_TEAL.hexval()[2:]}' >{_sanitize(self.model_name)}</font> &nbsp;|&nbsp; "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Footer"]
        ))

        doc.build(story, onFirstPage=self._draw_bg, onLaterPages=self._draw_bg)

    # ── Page background ───────────────────────────────────────────────────────

    def _draw_bg(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, self.PAGE_W, self.PAGE_H, fill=1, stroke=0)
        # Thin top accent bar
        canvas.setFillColor(ACCENT_BLUE)
        canvas.rect(0, self.PAGE_H - 3, self.PAGE_W, 3, fill=1, stroke=0)
        # Page number (skip cover)
        if doc.page > 1:
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(TEXT_MUTED)
            canvas.drawRightString(
                self.PAGE_W - self.MARGIN,
                10 * mm,
                f"Page {doc.page}"
            )
        canvas.restoreState()

    # ── Cover page ────────────────────────────────────────────────────────────

    def _cover(self, r, styles) -> list:
        story = []
        story.append(Spacer(1, 20 * mm))

        # Tool name
        story.append(Paragraph(
            "SKILL SECURITY EVALUATOR",
            styles["CoverTool"]
        ))
        story.append(Spacer(1, 3 * mm))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT_BLUE))
        story.append(Spacer(1, 8 * mm))

        # Skill name
        story.append(Paragraph(
            f"Security Report",
            styles["CoverLabel"]
        ))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            _sanitize(r.skill_name),
            styles["CoverTitle"]
        ))
        story.append(Spacer(1, 10 * mm))

        # Risk badge
        risk_color = SEV_COLORS.get(r.overall_risk, TEXT_MUTED)
        risk_bg    = SEV_BG.get(r.overall_risk, HexColor("#1E293B"))
        badge = Table(
            [[Paragraph(
                f"<font color='#{risk_color.hexval()[2:]}' size='18'>"
                f"<b>{r.overall_risk} RISK</b></font>",
                styles["Center"]
            )]],
            colWidths=[80 * mm],
            rowHeights=[14 * mm],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), risk_bg),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [4]),
            ("BOX",          (0, 0), (-1, -1), 1.5, risk_color),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(badge)
        story.append(Spacer(1, 10 * mm))

        # CVSS score big display
        story.append(Paragraph(
            f"<font size='48' color='#{risk_color.hexval()[2:]}'>"
            f"<b>{r.cvss_base_score:.1f}</b></font>"
            f"<font size='18' color='#{TEXT_SECONDARY.hexval()[2:]}'> / 10</font>",
            styles["Center"]
        ))
        story.append(Paragraph(
            f"<font color='#{TEXT_SECONDARY.hexval()[2:]}'>CVSS v3.1 Base Score — "
            f"{r.cvss_severity}</font>",
            styles["Center"]
        ))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(
            f"<font size='8' color='#{TEXT_MUTED.hexval()[2:]}'>{r.cvss_vector}</font>",
            styles["Center"]
        ))
        story.append(Spacer(1, 12 * mm))
        story.append(HRFlowable(width="60%", thickness=0.5, color=BORDER_COLOR))
        story.append(Spacer(1, 6 * mm))

        # Meta info table
        meta = [
            ["Skill File",      _sanitize(r.filename)],
            ["Vulnerabilities", str(r.vulnerability_count)],
            ["Evaluated by",    _sanitize(self.model_name)],
            ["Date",            datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ]
        meta_tbl = Table(
            [[Paragraph(k, styles["MetaKey"]), Paragraph(v, styles["MetaVal"])]
             for k, v in meta],
            colWidths=[40 * mm, 110 * mm],
            hAlign="CENTER",
        )
        meta_tbl.setStyle(TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.5, BORDER_COLOR),
        ]))
        story.append(meta_tbl)
        return story

    # ── Summary + CVSS table ──────────────────────────────────────────────────

    def _summary_section(self, r, styles) -> list:
        story = []

        # Executive summary
        story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(_sanitize(r.executive_summary), styles["BodyText"]))
        story.append(Spacer(1, 4 * mm))

        # Skill purpose
        if r.skill_purpose_analysis:
            story.append(Paragraph("Skill Purpose", styles["SubTitle"]))
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph(_sanitize(r.skill_purpose_analysis), styles["BodyText"]))
            story.append(Spacer(1, 6 * mm))

        story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR))
        story.append(Spacer(1, 6 * mm))

        # CVSS v3.1 Metrics table
        story.append(Paragraph("CVSS v3.1 Base Metrics", styles["SectionTitle"]))
        story.append(Spacer(1, 3 * mm))

        risk_color = SEV_COLORS.get(r.overall_risk, TEXT_MUTED)

        # Score bars row
        score_data = [
            [
                Paragraph("<b>Impact Score</b>", styles["MetaKey"]),
                _score_bar(r.impact_score, risk_color, 90),
                Paragraph(f"<b>{r.impact_score:.1f}</b> / 10", styles["ScoreNum"]),
                Paragraph("<b>Exploitability</b>", styles["MetaKey"]),
                _score_bar(r.exploitability_score, ACCENT_BLUE, 90),
                Paragraph(f"<b>{r.exploitability_score:.1f}</b> / 10", styles["ScoreNum"]),
            ]
        ]
        score_tbl = Table(
            score_data,
            colWidths=[32*mm, 30*mm, 18*mm, 32*mm, 30*mm, 18*mm],
        )
        score_tbl.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 2),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
        ]))
        story.append(score_tbl)
        story.append(Spacer(1, 4 * mm))

        # 8 metric rows
        metrics = [
            ("Attack Vector",       r.attack_vector),
            ("Attack Complexity",   r.attack_complexity),
            ("Privileges Required", r.privileges_required),
            ("User Interaction",    r.user_interaction),
            ("Scope",               r.scope),
            ("Confidentiality",     r.confidentiality_impact),
            ("Integrity",           r.integrity_impact),
            ("Availability",        r.availability_impact),
        ]
        # Two-column layout
        rows = []
        for i in range(0, len(metrics), 2):
            left  = metrics[i]
            right = metrics[i + 1] if i + 1 < len(metrics) else ("", "")
            rows.append([
                Paragraph(left[0],  styles["MetaKey"]),
                Paragraph(_sanitize(left[1]),  styles["MetaVal"]),
                Paragraph(right[0], styles["MetaKey"]),
                Paragraph(_sanitize(right[1]), styles["MetaVal"]),
            ])

        m_tbl = Table(rows, colWidths=[38*mm, 42*mm, 38*mm, 42*mm])
        m_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), CARD_BG),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (1, 0), (1, -1),  0.5, BORDER_COLOR),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(m_tbl)

        # Vector string
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            f"<font size='8' color='#{TEXT_MUTED.hexval()[2:]}'>"
            f"Vector: {_sanitize(r.cvss_vector)}</font>",
            styles["BodyText"]
        ))
        return story

    # ── Individual vulnerability section ─────────────────────────────────────

    def _vuln_section(self, v, styles) -> list:
        sev_color = SEV_COLORS.get(v.severity, TEXT_MUTED)
        sev_bg    = SEV_BG.get(v.severity, HexColor("#1E293B"))

        # Header bar: ID + title + severity badge
        header_data = [[
            Paragraph(
                f"<font color='#{ACCENT_BLUE.hexval()[2:]}'><b>{_sanitize(v.id)}</b></font>"
                f"  <font color='#{TEXT_PRIMARY.hexval()[2:]}'>{_sanitize(v.title)}</font>",
                styles["VulnTitle"]
            ),
            Paragraph(
                f"<font color='#{sev_color.hexval()[2:]}'><b>{v.severity}</b></font>",
                styles["SevBadge"]
            ),
        ]]
        header_tbl = Table(header_data, colWidths=[130*mm, 30*mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), CARD_BG),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (0, -1),  8),
            ("RIGHTPADDING",  (-1,0), (-1,-1),  8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (1, 0), (1, -1),  "RIGHT"),
            ("LINEABOVE",     (0, 0), (-1, 0),  1.5, sev_color),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))

        # Category row
        cat_row = Table([[
            Paragraph(f"<b>Category:</b>  {_sanitize(v.category)}", styles["MetaVal"]),
        ]], colWidths=[160*mm])
        cat_row.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#1E2030")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))

        body_parts = []

        # Affected content block
        if v.affected_content:
            body_parts.append(Paragraph(
                "<font color='#F97316'><b>Affected Content</b></font>",
                styles["FieldLabel"]
            ))
            body_parts.append(Spacer(1, 1*mm))
            body_parts.append(self._code_block(v.affected_content, styles))
            body_parts.append(Spacer(1, 3*mm))

        # Why dangerous
        if v.explanation:
            body_parts.append(Paragraph(
                "<font color='#EAB308'><b>Why It Is Dangerous</b></font>",
                styles["FieldLabel"]
            ))
            body_parts.append(Spacer(1, 1*mm))
            body_parts.append(Paragraph(_sanitize(v.explanation), styles["BodyText"]))
            body_parts.append(Spacer(1, 3*mm))

        # Attack scenario
        if v.attack_scenario:
            body_parts.append(Paragraph(
                "<font color='#EF4444'><b>Attack Scenario</b></font>",
                styles["FieldLabel"]
            ))
            body_parts.append(Spacer(1, 1*mm))
            for line in v.attack_scenario.split("\n"):
                line = line.strip()
                if line:
                    body_parts.append(Paragraph(
                        f"<font color='#{TEXT_SECONDARY.hexval()[2:]}'>"
                        f"{_sanitize(line)}</font>",
                        styles["StepText"]
                    ))
            body_parts.append(Spacer(1, 3*mm))

        # Remediation
        if v.remediation:
            body_parts.append(Paragraph(
                "<font color='#22C55E'><b>Remediation</b></font>",
                styles["FieldLabel"]
            ))
            body_parts.append(Spacer(1, 1*mm))
            body_parts.append(Paragraph(_sanitize(v.remediation), styles["BodyText"]))

        body_tbl = Table(
            [[Spacer(1, 0)]] + [[p] for p in body_parts] + [[Spacer(1, 2*mm)]],
            colWidths=[160*mm],
        )
        body_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#12151F")),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("LINEAFTER",     (0, 0), (0, -1),  3, sev_color),
        ]))

        block = KeepTogether([
            header_tbl,
            cat_row,
            body_tbl,
            Spacer(1, 5*mm),
        ])
        return [block]

    # ── Patterns + remediation priority section ───────────────────────────────

    def _patterns_section(self, r, styles) -> list:
        story = []

        if r.dangerous_patterns:
            story.append(Paragraph("Dangerous Patterns Found", styles["SectionTitle"]))
            story.append(Spacer(1, 3*mm))
            for p in r.dangerous_patterns:
                story.append(Paragraph(
                    f"<font color='#EF4444'>&#x2022;</font>  {_sanitize(p)}",
                    styles["BulletText"]
                ))
            story.append(Spacer(1, 5*mm))

        if r.safe_patterns:
            story.append(Paragraph("Safe Practices Observed", styles["SectionTitle"]))
            story.append(Spacer(1, 3*mm))
            for p in r.safe_patterns:
                story.append(Paragraph(
                    f"<font color='#22C55E'>&#x2022;</font>  {_sanitize(p)}",
                    styles["BulletText"]
                ))
            story.append(Spacer(1, 5*mm))

        if r.remediation_priority:
            story.append(Paragraph("Remediation Priority", styles["SectionTitle"]))
            story.append(Spacer(1, 3*mm))
            for i, step in enumerate(r.remediation_priority.split("\n"), 1):
                step = step.strip()
                if step:
                    story.append(Paragraph(
                        f"<font color='#{ACCENT_TEAL.hexval()[2:]}'><b>{i}.</b></font>  "
                        f"{_sanitize(step.lstrip('0123456789. '))}",
                        styles["StepText"]
                    ))
            story.append(Spacer(1, 4*mm))

        return story

    # ── Code block helper ─────────────────────────────────────────────────────

    def _code_block(self, text: str, styles) -> Table:
        lines = _sanitize(text[:600]).split("\n")
        rendered = [
            Paragraph(
                f"<font name='Courier' size='8' color='#{ACCENT_TEAL.hexval()[2:]}'>"
                f"{line if line.strip() else '&nbsp;'}</font>",
                styles["CodeLine"]
            )
            for line in lines[:20]
        ]
        t = Table([[r] for r in rendered], colWidths=[155*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), CODE_BG),
            ("TOPPADDING",    (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#30363D")),
            ("LINEAFTER",     (0, 0), (0, -1),  3, ACCENT_BLUE),
        ]))
        return t

    # ── Styles ────────────────────────────────────────────────────────────────

    def _make_styles(self):
        base    = getSampleStyleSheet()
        content_w = self.PAGE_W - 2 * self.MARGIN

        def s(name, parent="Normal", **kw) -> ParagraphStyle:
            return ParagraphStyle(name, parent=base[parent], **kw)

        return {
            # Cover
            "CoverTool": s("CoverTool", fontSize=10, textColor=TEXT_MUTED,
                           alignment=TA_CENTER, spaceAfter=4),
            "CoverLabel": s("CoverLabel", fontSize=11, textColor=TEXT_SECONDARY,
                            alignment=TA_CENTER, spaceAfter=2),
            "CoverTitle": s("CoverTitle", fontSize=26, textColor=TEXT_PRIMARY,
                            alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=6),
            "Center": s("Center", alignment=TA_CENTER, textColor=TEXT_PRIMARY),

            # Section headers
            "SectionTitle": s("SectionTitle", fontSize=14, textColor=ACCENT_BLUE,
                               fontName="Helvetica-Bold", spaceAfter=4,
                               borderPad=0),
            "SubTitle": s("SubTitle", fontSize=11, textColor=ACCENT_TEAL,
                           fontName="Helvetica-Bold", spaceAfter=2),

            # Body text
            "BodyText": s("BodyText", fontSize=9, textColor=TEXT_SECONDARY,
                           leading=14, alignment=TA_JUSTIFY, spaceAfter=2),
            "BulletText": s("BulletText", fontSize=9, textColor=TEXT_SECONDARY,
                             leading=14, leftIndent=8, spaceAfter=2),
            "StepText": s("StepText", fontSize=9, textColor=TEXT_SECONDARY,
                           leading=13, leftIndent=10, spaceAfter=2),
            "FieldLabel": s("FieldLabel", fontSize=9, textColor=TEXT_PRIMARY,
                             fontName="Helvetica-Bold", spaceAfter=1),

            # Vuln header
            "VulnTitle": s("VulnTitle", fontSize=10, textColor=TEXT_PRIMARY,
                            fontName="Helvetica-Bold", leading=14),
            "SevBadge": s("SevBadge", fontSize=9, fontName="Helvetica-Bold",
                           alignment=TA_RIGHT),

            # Meta / table cells
            "MetaKey": s("MetaKey", fontSize=8, textColor=TEXT_MUTED,
                          fontName="Helvetica-Bold"),
            "MetaVal": s("MetaVal", fontSize=8, textColor=TEXT_PRIMARY),
            "ScoreNum": s("ScoreNum", fontSize=8, textColor=TEXT_PRIMARY,
                           fontName="Helvetica-Bold", alignment=TA_CENTER),

            # Code
            "CodeLine": s("CodeLine", fontSize=8, textColor=ACCENT_TEAL,
                           fontName="Courier", leading=10),

            # Footer
            "Footer": s("Footer", fontSize=7, textColor=TEXT_MUTED,
                          alignment=TA_CENTER),
        }
    