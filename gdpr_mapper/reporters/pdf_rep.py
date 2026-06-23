"""
PDF reporter — generates a professional compliance assessment report using ReportLab.

Structure:
  Page 1: Cover — system name, date, overall score badge
  Page 2: Executive Summary — key metrics + critical gaps
  Page 3: Article Summary table
  Pages 4+: Per-article detailed findings
  Final: Remediation Roadmap (priority-ordered action table)
"""

from __future__ import annotations
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether,
)
from reportlab.platypus.flowables import Flowable

from ..models.compliance import ComplianceReport, ComplianceStatus, Severity

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
_GREEN = colors.HexColor("#2E7D32")
_AMBER = colors.HexColor("#F57F17")
_RED = colors.HexColor("#B71C1C")
_DARK_BLUE = colors.HexColor("#0D2137")
_LIGHT_BLUE = colors.HexColor("#E3F2FD")
_GREY = colors.HexColor("#78909C")
_LIGHT_GREY = colors.HexColor("#F5F5F5")
_WHITE = colors.white
_BLACK = colors.black

_STATUS_COLOUR = {
    ComplianceStatus.SATISFIED: _GREEN,
    ComplianceStatus.PARTIAL: _AMBER,
    ComplianceStatus.GAP: _RED,
    ComplianceStatus.NA: _GREY,
}

_STATUS_LABEL = {
    ComplianceStatus.SATISFIED: "SATISFIED",
    ComplianceStatus.PARTIAL: "PARTIAL",
    ComplianceStatus.GAP: "GAP",
    ComplianceStatus.NA: "N/A",
}

_SEV_COLOUR = {
    Severity.CRITICAL: _RED,
    Severity.HIGH: colors.HexColor("#E64A19"),
    Severity.MEDIUM: _AMBER,
    Severity.LOW: colors.HexColor("#1976D2"),
    Severity.INFO: _GREY,
}


# ---------------------------------------------------------------------------
# Custom flowable: coloured badge
# ---------------------------------------------------------------------------
class Badge(Flowable):
    def __init__(self, text: str, bg: colors.Color, fg: colors.Color = _WHITE,
                 width: float = 90, height: float = 18, font_size: float = 9):
        super().__init__()
        self.text = text
        self.bg = bg
        self.fg = fg
        self.width = width
        self.height = height
        self.font_size = font_size

    def wrap(self, *args):
        return self.width, self.height

    def draw(self):
        self.canv.setFillColor(self.bg)
        self.canv.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=0)
        self.canv.setFillColor(self.fg)
        self.canv.setFont("Helvetica-Bold", self.font_size)
        self.canv.drawCentredString(self.width / 2, (self.height - self.font_size) / 2 + 1, self.text)


# ---------------------------------------------------------------------------
# Page templates
# ---------------------------------------------------------------------------
def _header_footer(canvas, doc, report: ComplianceReport) -> None:
    canvas.saveState()
    W, H = A4
    # Header bar
    canvas.setFillColor(_DARK_BLUE)
    canvas.rect(0, H - 20 * mm, W, 20 * mm, fill=1, stroke=0)
    canvas.setFillColor(_WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15 * mm, H - 13 * mm, "UK GDPR Security Compliance Assessment")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(W - 15 * mm, H - 13 * mm, report.system_name)
    # Footer
    canvas.setFillColor(_LIGHT_GREY)
    canvas.rect(0, 0, W, 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(_GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15 * mm, 4 * mm,
                      f"Generated {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')} | "
                      f"gdpr-security-mapper v1.0.0 | CONFIDENTIAL")
    canvas.drawRightString(W - 15 * mm, 4 * mm, f"Page {doc.page}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------
def _styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("H1", fontSize=22, textColor=_DARK_BLUE, spaceAfter=6,
                             fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("H2", fontSize=14, textColor=_DARK_BLUE, spaceAfter=4,
                             fontName="Helvetica-Bold", spaceBefore=8),
        "h3": ParagraphStyle("H3", fontSize=11, textColor=_DARK_BLUE, spaceAfter=3,
                             fontName="Helvetica-Bold", spaceBefore=6),
        "body": ParagraphStyle("Body", fontSize=9, textColor=_BLACK, spaceAfter=3,
                               fontName="Helvetica", leading=13),
        "small": ParagraphStyle("Small", fontSize=8, textColor=_GREY, spaceAfter=2,
                                fontName="Helvetica"),
        "bold": ParagraphStyle("Bold", fontSize=9, textColor=_BLACK, fontName="Helvetica-Bold"),
        "table_hdr": ParagraphStyle("TblHdr", fontSize=8, textColor=_WHITE,
                                    fontName="Helvetica-Bold", alignment=TA_CENTER),
        "table_cell": ParagraphStyle("TblCell", fontSize=8, textColor=_BLACK,
                                     fontName="Helvetica", leading=11),
        "table_cell_small": ParagraphStyle("TblCellSm", fontSize=7, textColor=_BLACK,
                                           fontName="Helvetica", leading=10),
    }


def _status_style(status: ComplianceStatus) -> TableStyle:
    c = _STATUS_COLOUR[status]
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
    ])


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------
def _cover_page(report: ComplianceReport, st: dict) -> list:
    elements = []
    elements.append(Spacer(1, 35 * mm))

    # Large score
    score_pct = report.overall_score * 100
    status = report.overall_status
    col = _STATUS_COLOUR[status]

    elements.append(Paragraph("UK GDPR Security Compliance Assessment", st["h1"]))
    elements.append(Paragraph(report.system_name, ParagraphStyle(
        "SystemName", fontSize=16, textColor=_GREY, fontName="Helvetica", spaceAfter=2)))
    if report.system_description:
        elements.append(Paragraph(report.system_description, st["small"]))
    elements.append(Spacer(1, 12 * mm))
    elements.append(HRFlowable(width="100%", thickness=2, color=_DARK_BLUE))
    elements.append(Spacer(1, 10 * mm))

    # Score box
    score_data = [[
        Paragraph(f"<b>{score_pct:.1f}%</b>", ParagraphStyle(
            "Score", fontSize=36, textColor=col, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<b>{_STATUS_LABEL[status]}</b>", ParagraphStyle(
            "StatusLabel", fontSize=20, textColor=col, fontName="Helvetica-Bold",
            alignment=TA_CENTER)),
    ]]
    score_tbl = Table(score_data, colWidths=[70 * mm, 100 * mm])
    score_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 2, col),
        ("BACKGROUND", (0, 0), (-1, -1), _LIGHT_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(score_tbl)
    elements.append(Spacer(1, 10 * mm))

    # Metadata table
    total = report.total_checks
    gaps = len(report.all_gaps)
    partials = len(report.all_partials)
    satisfied = total - gaps - partials
    meta = [
        ["Generated", report.generated_at.strftime("%d %B %Y, %H:%M UTC")],
        ["Config Source", report.config_source],
        ["Articles Assessed", str(len(report.articles))],
        ["Total Checks", str(total)],
        ["Satisfied", str(satisfied)],
        ["Partial", str(partials)],
        ["Gaps", str(gaps)],
        ["Regulatory Framework", "UK GDPR (retained EU law post-Brexit)"],
        ["Supervisory Authority", "Information Commissioner's Office (ICO)"],
    ]
    meta_tbl = Table(meta, colWidths=[55 * mm, 115 * mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), _DARK_BLUE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, _GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 8 * mm))
    elements.append(Paragraph(
        "This report is CONFIDENTIAL and intended solely for the named organisation's "
        "internal use. It does not constitute legal advice.",
        ParagraphStyle("Disclaimer", fontSize=7, textColor=_GREY, fontName="Helvetica-Oblique")
    ))
    elements.append(PageBreak())
    return elements


def _exec_summary(report: ComplianceReport, st: dict) -> list:
    elements = [Paragraph("Executive Summary", st["h2"]), Spacer(1, 3 * mm)]

    score_pct = report.overall_score * 100
    status = report.overall_status
    col = _STATUS_COLOUR[status]

    elements.append(Paragraph(
        f"This assessment evaluated <b>{report.system_name}</b> against 10 areas of UK GDPR, "
        f"running <b>{report.total_checks} individual compliance checks</b>. The system achieved "
        f"an overall compliance score of <b>{score_pct:.1f}%</b>, rated as "
        f"<b>{_STATUS_LABEL[status]}</b>.",
        st["body"],
    ))
    elements.append(Spacer(1, 4 * mm))

    # Article scorecard
    scorecard_data = [["Article", "Title", "Score", "Status"]]
    for art in report.articles:
        scorecard_data.append([
            art.article_id,
            art.article_title,
            f"{art.score * 100:.0f}%",
            _STATUS_LABEL[art.status],
        ])

    scorecard = Table(scorecard_data, colWidths=[28 * mm, 90 * mm, 16 * mm, 26 * mm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, _GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
    ]
    for i, art in enumerate(report.articles, 1):
        c = _STATUS_COLOUR[art.status]
        style_cmds.append(("TEXTCOLOR", (3, i), (3, i), c))
        style_cmds.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

    scorecard.setStyle(TableStyle(style_cmds))
    elements.append(scorecard)
    elements.append(Spacer(1, 5 * mm))

    # Critical gaps panel
    critical_gaps = [g for g in report.all_gaps if g.severity in (Severity.CRITICAL, Severity.HIGH)][:6]
    if critical_gaps:
        elements.append(Paragraph("Critical & High Priority Gaps", st["h3"]))
        gap_data = [["#", "Check ID", "Article", "Control", "Finding"]]
        for i, gap in enumerate(critical_gaps, 1):
            finding = gap.finding[:80] + "..." if len(gap.finding) > 80 else gap.finding
            gap_data.append([str(i), gap.check_id, gap.article_id, gap.control_name, finding])
        gap_tbl = Table(gap_data, colWidths=[8 * mm, 20 * mm, 24 * mm, 40 * mm, 68 * mm])
        gap_style = [
            ("BACKGROUND", (0, 0), (-1, 0), _RED),
            ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.5, _GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFEBEE"), _WHITE]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        gap_tbl.setStyle(TableStyle(gap_style))
        elements.append(gap_tbl)

    elements.append(PageBreak())
    return elements


def _article_detail_section(article, st: dict) -> list:
    col = _STATUS_COLOUR[article.status]
    elements = []

    header = (
        f"{article.article_id} — {article.article_title}  "
        f"[{_STATUS_LABEL[article.status]}  {article.score * 100:.0f}%]"
    )
    elements.append(Paragraph(header, ParagraphStyle(
        "ArtHdr", fontSize=12, textColor=col, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2)))
    elements.append(Paragraph(article.article_summary, st["small"]))
    elements.append(Spacer(1, 3 * mm))

    rows = [["Check ID", "Control", "Status", "Severity", "Evidence / Finding"]]
    for chk in article.checks:
        finding_text = (chk.finding or chk.evidence)[:120]
        if len(chk.finding or chk.evidence) > 120:
            finding_text += "..."
        rows.append([
            chk.check_id,
            chk.control_name,
            _STATUS_LABEL[chk.status],
            chk.severity.value,
            finding_text,
        ])

    tbl = Table(rows, colWidths=[20 * mm, 42 * mm, 20 * mm, 18 * mm, 60 * mm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, _GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, chk in enumerate(article.checks, 1):
        c = _STATUS_COLOUR[chk.status]
        style_cmds.append(("TEXTCOLOR", (2, i), (2, i), c))
        style_cmds.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        sc = _SEV_COLOUR.get(chk.severity, _GREY)
        style_cmds.append(("TEXTCOLOR", (3, i), (3, i), sc))

    tbl.setStyle(TableStyle(style_cmds))
    elements.append(KeepTogether([tbl, Spacer(1, 4 * mm)]))
    return elements


def _remediation_roadmap(report: ComplianceReport, st: dict) -> list:
    elements = [PageBreak(), Paragraph("Remediation Roadmap", st["h2"]),
                Paragraph(
                    "Priority-ordered remediation actions. Address CRITICAL and HIGH severity gaps first.",
                    st["body"]),
                Spacer(1, 4 * mm)]

    all_issues = report.all_gaps + report.all_partials
    if not all_issues:
        elements.append(Paragraph("No remediation actions required — all controls satisfied.", st["body"]))
        return elements

    _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                  Severity.LOW: 3, Severity.INFO: 4}
    sorted_issues = sorted(all_issues, key=lambda c: _sev_order.get(c.severity, 5))

    rows = [["#", "Severity", "Check", "Article", "Control", "Recommended Action"]]
    for i, issue in enumerate(sorted_issues[:30], 1):
        rem = issue.remediation[:130] + "..." if len(issue.remediation) > 130 else issue.remediation
        rows.append([
            str(i),
            issue.severity.value,
            issue.check_id,
            issue.article_id,
            issue.control_name,
            rem,
        ])

    tbl = Table(rows, colWidths=[8 * mm, 18 * mm, 18 * mm, 22 * mm, 36 * mm, 58 * mm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), _DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, _GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, issue in enumerate(sorted_issues[:30], 1):
        sc = _SEV_COLOUR.get(issue.severity, _GREY)
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), sc))
        style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(style_cmds))
    elements.append(tbl)
    return elements


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
class PdfReporter:
    def __init__(self, output: str | Path) -> None:
        self.output = Path(output)

    def render(self, report: ComplianceReport) -> None:
        st = _styles()
        margin = 18 * mm

        doc = SimpleDocTemplate(
            str(self.output),
            pagesize=A4,
            leftMargin=margin,
            rightMargin=margin,
            topMargin=25 * mm,
            bottomMargin=18 * mm,
            title=f"GDPR Compliance Report — {report.system_name}",
            author="gdpr-security-mapper",
            subject="UK GDPR Security Compliance Assessment",
        )

        story: list = []
        story += _cover_page(report, st)
        story += _exec_summary(report, st)

        story.append(Paragraph("Detailed Findings by Article", st["h2"]))
        story.append(Spacer(1, 3 * mm))
        for art in report.articles:
            story += _article_detail_section(art, st)

        story += _remediation_roadmap(report, st)

        doc.build(
            story,
            onFirstPage=lambda c, d: _header_footer(c, d, report),
            onLaterPages=lambda c, d: _header_footer(c, d, report),
        )
