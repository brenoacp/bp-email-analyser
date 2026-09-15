import io
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Circle, Wedge, String, Rect
from reportlab.lib import colors
from app.core.schemas import EmailAnalysisResponse


def _create_risk_gauge_drawing(score: int, risk_level: str) -> Drawing:
    d = Drawing(135, 135)
    cx, cy = 67.5, 72

    rl_upper = (risk_level or "").upper()
    if rl_upper == "CRITICAL" or score > 75:
        theme_color = colors.HexColor("#dc2626")
        bg_accent = colors.HexColor("#fef2f2")
    elif rl_upper == "HIGH" or score > 50:
        theme_color = colors.HexColor("#ea580c")
        bg_accent = colors.HexColor("#fff7ed")
    elif rl_upper == "INFO" or score > 25:
        theme_color = colors.HexColor("#d97706")
        bg_accent = colors.HexColor("#fffbeb")
    else:
        theme_color = colors.HexColor("#059669")
        bg_accent = colors.HexColor("#ecfdf5")

    # Card background frame
    d.add(Rect(5, 5, 125, 125, rx=8, ry=8, fillColor=bg_accent, strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=0.5))

    # Title above gauge
    d.add(String(cx, 115, "SCORE DE RISCO", textAnchor="middle", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.HexColor("#64748b")))

    # Track circle
    d.add(Circle(cx, cy, 36, strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=7.5, fillColor=None))

    # Active score arc
    score_clamped = max(0, min(100, score))
    if score_clamped >= 100:
        d.add(Circle(cx, cy, 36, strokeColor=theme_color, strokeWidth=7.5, fillColor=None))
    elif score_clamped > 0:
        d.add(Wedge(cx, cy, 39.75, 90 - score_clamped * 3.6, 90, strokeColor=None, fillColor=theme_color))
        d.add(Circle(cx, cy, 32.25, strokeColor=None, fillColor=bg_accent))

    # Number inside gauge
    d.add(String(cx, cy + 1.5, str(score_clamped), textAnchor="middle", fontName="Helvetica-Bold", fontSize=18, fillColor=theme_color))
    d.add(String(cx, cy - 9.5, "/ 100", textAnchor="middle", fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#64748b")))

    # Badge pill below gauge
    d.add(Rect(cx - 36, 14, 72, 16, rx=8, ry=8, fillColor=theme_color, strokeColor=None))
    d.add(String(cx, 18.5, rl_upper, textAnchor="middle", fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.white))

    return d


def generate_pdf_report(analysis: EmailAnalysisResponse) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )

    risk_label = (
        analysis.summary.risk_level.value
        if hasattr(analysis.summary.risk_level, "value")
        else str(analysis.summary.risk_level)
    )

    story = []
    story.append(Paragraph("Relatório Técnico de Forense de E-mail (SOC)", title_style))
    story.append(
        Paragraph(
            f"<b>Data da Análise:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"<b>Score de Risco:</b> {analysis.summary.score}/100 ({risk_label})",
            styles["Normal"],
        )
    )
    raw_hash = xml_escape(analysis.raw_header_hash[:32]) if analysis.raw_header_hash else ""
    story.append(Paragraph(f"<b>Hash SHA-256 do Cabeçalho:</b> <code>{raw_hash}...</code>", styles["Normal"]))
    story.append(Spacer(1, 14))

    # Executive Summary Box with Visual Score Gauge
    gauge_drawing = _create_risk_gauge_drawing(analysis.summary.score, risk_label)

    safe_verdict = xml_escape(analysis.summary.verdict_text or "")
    safe_rec = xml_escape(analysis.summary.recommendation or "")
    safe_from_name = xml_escape(analysis.identity.from_display_name or "")
    safe_from_addr = xml_escape(analysis.identity.from_address or "")
    safe_origin_ip = xml_escape(analysis.origin_ip.ip or "Desconhecido")
    safe_origin_country = xml_escape(analysis.origin_ip.country or "N/A")
    safe_origin_org = xml_escape(analysis.origin_ip.org or "N/A")

    summary_data = [
        [Paragraph("<b>Veredito Geral:</b>", styles["Normal"]), Paragraph(safe_verdict, styles["Normal"])],
        [Paragraph("<b>Recomendação:</b>", styles["Normal"]), Paragraph(safe_rec, styles["Normal"])],
        [Paragraph("<b>Remetente (From):</b>", styles["Normal"]), Paragraph(f"{safe_from_name} &lt;{safe_from_addr}&gt;", styles["Normal"])],
        [Paragraph("<b>IP de Origem:</b>", styles["Normal"]), Paragraph(f"{safe_origin_ip} ({safe_origin_country}, {safe_origin_org})", styles["Normal"])],
    ]
    t_summary_inner = Table(summary_data, colWidths=[105, 295])
    t_summary_inner.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e2e8f0")),
    ]))

    t_executive = Table([[gauge_drawing, t_summary_inner]], colWidths=[140, 400])
    t_executive.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
        ("LINEBEFORE", (1, 0), (1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_executive)
    story.append(Spacer(1, 14))

    # Findings Table
    story.append(Paragraph("<b>Evidências Técnicas e Fatores de Risco</b>", styles["Heading2"]))
    findings_data = [["Categoria", "Achado", "Severidade", "Pontos"]]
    for f in analysis.findings:
        sev_label = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        findings_data.append([f.category, f.title, str(sev_label), f"+{f.points}"])
    if len(findings_data) == 1:
        findings_data.append(["N/A", "Nenhuma evidência de risco detectada", "SAFE", "0"])

    t_findings = Table(findings_data, colWidths=[110, 260, 90, 80])
    t_findings.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_findings)
    story.append(Spacer(1, 14))

    # Hops Table
    story.append(Paragraph("<b>Cadeia de Saltos (Received Hops)</b>", styles["Heading2"]))
    hops_data = [["Salto", "IP", "FCrDNS", "Localização / ASN", "Latência"]]
    for h in analysis.hops:
        fcrdns_str = "OK" if h.fcrdns_passed else ("Falha" if h.fcrdns_passed is False else "N/A")
        loc_str = f"{h.country or ''} {h.org or ''}".strip() or "N/A"
        hops_data.append([f"#{h.order}", h.ip or "N/A", fcrdns_str, loc_str, f"+{h.delay_seconds}s"])

    t_hops = Table(hops_data, colWidths=[50, 110, 70, 230, 80])
    t_hops.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_hops)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
