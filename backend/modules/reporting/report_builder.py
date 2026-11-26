"""
PDF report export - turns one target's saved result files into a single,
clean PDF instead of a raw dump of every tool's text output.

Only tools that actually have a result on disk are included (nothing for
"not run yet" clutters the file). Lines matching a short list of
attention keywords (VULNERABLE, POSSIBLE, INSECURE, MISSING, EXPOSED,
UNESCAPED) are pulled out and shown in red/bold so a reader can scan
straight to what matters.
"""
import io
import os
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ACCENT = colors.HexColor("#1f3d2b")
DANGER = colors.HexColor("#b3261e")
MUTED = colors.HexColor("#5b625f")
RULE = colors.HexColor("#d7dad8")

ATTENTION_RE = re.compile(
    r"\b(VULNERABLE|POSSIBLE [A-Za-z]+|INSECURE|MISSING|EXPOSED|UNESCAPED)\b"
)

# (result filename, section title) - in report order. Only files that exist
# and are non-empty are rendered.
SECTIONS = [
    ("subdomains.txt", "Subdomain Enumeration"),
    ("live_hosts.txt", "Live Host Probe"),
    ("waf.txt", "WAF Detection"),
    ("ports.txt", "Port Scan"),
    ("dns_records.txt", "DNS Records"),
    ("whois.txt", "WHOIS / RDAP Lookup"),
    ("endpoints.txt", "Directory / Endpoint Discovery"),
    ("wayback.txt", "Wayback Machine URLs"),
    ("js_files.txt", "JS Files Extracted"),
    ("jsluice_urls.txt", "JS URLs (jsluice)"),
    ("jsluice_secrets.txt", "JS Secrets (jsluice)"),
    ("url_patterns.txt", "URL Pattern Filter"),
    ("techinfo.txt", "Tech Fingerprint + TLS"),
    ("xss_probe.txt", "XSS Reflection Prober"),
    ("open_redirect_probe.txt", "Open Redirect Prober"),
    ("sqli_probe.txt", "SQL Injection Error-Based Prober"),
    ("lfi_probe.txt", "LFI / Path Traversal Prober"),
    ("tls_checks.txt", "TLS / SSL Deep Checks"),
    ("web_misconfig.txt", "Web Misconfiguration Checker"),
    ("nse_vuln.txt", "Nmap Vuln Scripts"),
    ("subdomain_takeover.txt", "Subdomain Takeover Checker"),
    ("cve_merge.txt", "CVE Lookup - merged (NVD + CIRCL)"),
]

MAX_LINES_PER_SECTION = 200  # keeps one noisy tool from blowing the PDF up to hundreds of pages


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("ReportTitle", parent=ss["Title"], fontSize=24, leading=28,
                           textColor=ACCENT, alignment=TA_CENTER, spaceAfter=6))
    ss.add(ParagraphStyle("ReportSubtitle", parent=ss["Normal"], fontSize=12, leading=16,
                           textColor=MUTED, alignment=TA_CENTER))
    ss.add(ParagraphStyle("Section", parent=ss["Heading2"], fontSize=14, leading=18,
                           textColor=ACCENT, spaceBefore=18, spaceAfter=8))
    ss.add(ParagraphStyle("AISection", parent=ss["Heading3"], fontSize=12, leading=15,
                           textColor=ACCENT, spaceBefore=12, spaceAfter=4))
    ss.add(ParagraphStyle("Line", parent=ss["Code"], fontSize=8.5, leading=11.5,
                           fontName="Courier", textColor=colors.HexColor("#1c1f1e")))
    ss.add(ParagraphStyle("LineAttn", parent=ss["Line"], textColor=DANGER))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontSize=10, leading=14))
    ss.add(ParagraphStyle("Footer", parent=ss["Normal"], fontSize=8, textColor=MUTED))
    return ss


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _read_lines(path: str):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _line_style(line: str, styles):
    return styles["LineAttn"] if ATTENTION_RE.search(line) else styles["Line"]


def _ai_summary_block(ai_report_text: str, styles):
    """Pull out just the "## Summary" section of the AI report (if present)
    for the front page - the rest of the AI report gets its own full section."""
    if not ai_report_text:
        return None
    m = re.search(r"##\s*Summary\s*\n(.+?)(?=\n##|\Z)", ai_report_text, re.S)
    if not m:
        return None
    text = m.group(1).strip()
    return Paragraph(_escape(text), styles["Body"])


def _markdown_lite_flowables(md_text: str, styles):
    """Very small Markdown -> Paragraph converter for the AI report body:
    ## headings, **bold**, - bullets. Matches the same subset the frontend's
    renderMarkdownLite() understands, just rendered as PDF flowables here."""
    flowables = []
    for raw in md_text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        inline = _escape(line)
        inline = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", inline)
        if line.startswith("## "):
            flowables.append(Paragraph(inline[3:], styles["AISection"]))
        elif line.startswith("# "):
            flowables.append(Paragraph(inline[2:], styles["Section"]))
        elif line.startswith("- "):
            flowables.append(Paragraph(f"&bull;&nbsp; {inline[2:]}", styles["Body"]))
        else:
            flowables.append(Paragraph(inline, styles["Body"]))
    return flowables


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(2 * cm, 1.2 * cm, "Penetration Testing Framework - generated report")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(meta: dict, target_path: str) -> bytes:
    styles = _styles()
    story = []

    # --- Cover ---
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("Penetration Test Report", styles["ReportTitle"]))
    story.append(Paragraph(meta.get("name", ""), styles["ReportSubtitle"]))
    story.append(Spacer(1, 1 * cm))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    info = Table(
        [["Target domain", meta.get("domain", "")], ["Generated", generated]],
        colWidths=[4 * cm, 10 * cm],
    )
    info.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, RULE),
    ]))
    story.append(info)

    ai_report_path = os.path.join(target_path, "ai_report.txt")
    ai_text = ""
    if os.path.isfile(ai_report_path):
        with open(ai_report_path, "r", encoding="utf-8", errors="ignore") as f:
            ai_text = f.read().strip()

    summary = _ai_summary_block(ai_text, styles) if ai_text else None
    if summary:
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph("Executive Summary", styles["Section"]))
        story.append(HRFlowable(width="100%", color=RULE, thickness=0.75))
        story.append(Spacer(1, 4))
        story.append(summary)
    story.append(PageBreak())

    # --- AI Analysis (full) ---
    if ai_text:
        story.append(Paragraph("AI Findings Analysis", styles["Section"]))
        story.append(HRFlowable(width="100%", color=RULE, thickness=0.75))
        story.extend(_markdown_lite_flowables(ai_text, styles))
        story.append(PageBreak())

    # --- Per-tool sections ---
    any_section = False
    for filename, title in SECTIONS:
        lines = _read_lines(os.path.join(target_path, filename))
        if not lines:
            continue
        any_section = True
        story.append(Paragraph(f"{title} <font color='#5b625f' size=9>({len(lines)} result(s))</font>",
                                styles["Section"]))
        story.append(HRFlowable(width="100%", color=RULE, thickness=0.75))
        story.append(Spacer(1, 4))
        shown = lines[:MAX_LINES_PER_SECTION]
        for line in shown:
            story.append(Paragraph(_escape(line), _line_style(line, styles)))
        if len(lines) > MAX_LINES_PER_SECTION:
            story.append(Paragraph(
                f"... {len(lines) - MAX_LINES_PER_SECTION} more line(s) omitted - see the full result in the app.",
                styles["Footer"]))

    if not any_section and not ai_text:
        story.append(Paragraph("No Recon or Vulnerability Scan tools have been run for this "
                                "target yet.", styles["Body"]))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2.2 * cm,
        title=f"Pentest Report - {meta.get('name', '')}",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
