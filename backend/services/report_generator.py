"""
PDF report generator using ReportLab Platypus.

Produces a professional layout (max ~15-20 pages) with:
- Header with PhishGuard branding
- Risk score gauge and classification badge
- Sections for each analyzer
- Findings table
- Disclaimer
"""
from __future__ import annotations

import io
import logging
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

log = logging.getLogger(__name__)

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm

_NAVY = colors.HexColor("#0B1220")
_EMERALD = colors.HexColor("#16A34A")
_WARNING = colors.HexColor("#F59E0B")
_DANGER = colors.HexColor("#DC2626")
_BG_LIGHT = colors.HexColor("#F8FAFC")
_TEXT_DARK = colors.HexColor("#111827")
_GRAY = colors.HexColor("#6B7280")
_WHITE = colors.white
_LIGHT_BORDER = colors.HexColor("#E5E7EB")

_MAX_TABLE_ROWS = 60


def _esc(text) -> str:
    if text is None:
        return "N/A"
    return escape(str(text)[:500])


def _risk_color(score) -> colors.Color:
    if score is None:
        return _GRAY
    if score < 30:
        return _EMERALD
    if score < 60:
        return _WARNING
    return _DANGER


def _classification_color(cls: str) -> colors.Color:
    cls = (cls or "").upper()
    if cls == "LEGITIMATE":
        return _EMERALD
    if cls == "SUSPICIOUS":
        return _WARNING
    return _DANGER


def _severity_color(sev: str) -> colors.Color:
    m = {
        "strong": _DANGER,
        "medium": _WARNING,
        "low": colors.HexColor("#3B82F6"),
        "positive": _EMERALD,
        "info": _GRAY,
    }
    return m.get(sev, _GRAY)


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "PGTitle", parent=base["Title"],
            fontName="Helvetica-Bold", fontSize=18, textColor=_NAVY,
            spaceAfter=6,
        ),
        "h1": ParagraphStyle(
            "PGH1", parent=base["Heading1"],
            fontName="Helvetica-Bold", fontSize=14, textColor=_NAVY,
            spaceBefore=14, spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "PGH2", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=11, textColor=_NAVY,
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "PGBody", parent=base["Normal"],
            fontName="Helvetica", fontSize=9, textColor=_TEXT_DARK,
            leading=13, spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "PGSmall", parent=base["Normal"],
            fontName="Helvetica", fontSize=7.5, textColor=_GRAY,
            leading=10,
        ),
        "center": ParagraphStyle(
            "PGCenter", parent=base["Normal"],
            fontName="Helvetica", fontSize=9, textColor=_TEXT_DARK,
            alignment=TA_CENTER, leading=13,
        ),
        "badge": ParagraphStyle(
            "PGBadge", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=13, alignment=TA_CENTER,
            textColor=_WHITE, leading=18,
        ),
        "score_big": ParagraphStyle(
            "PGScoreBig", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=28, alignment=TA_CENTER,
            textColor=_NAVY, leading=34,
        ),
        "table_header": ParagraphStyle(
            "PGTableH", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=8, textColor=_WHITE,
            leading=11,
        ),
        "table_cell": ParagraphStyle(
            "PGTableC", parent=base["Normal"],
            fontName="Helvetica", fontSize=8, textColor=_TEXT_DARK,
            leading=11,
        ),
        "disclaimer": ParagraphStyle(
            "PGDisclaimer", parent=base["Normal"],
            fontName="Helvetica-Oblique", fontSize=7.5, textColor=_GRAY,
            leading=10, spaceBefore=12,
        ),
    }


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(_NAVY)
    canvas.rect(0, PAGE_H - 28 * mm, PAGE_W, 28 * mm, fill=1, stroke=0)
    canvas.setFillColor(_WHITE)
    canvas.setFont("Helvetica-Bold", 16)
    canvas.drawString(MARGIN, PAGE_H - 18 * mm, "PhishGuard")
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN, PAGE_H - 24 * mm, "Phishing URL Analysis Report")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_GRAY)
    canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}")
    canvas.drawString(MARGIN, 10 * mm, "PhishGuard - Automated Phishing Detection")
    canvas.restoreState()


def _score_section(report: dict, styles: dict) -> list:
    elements = []
    score = report.get("risk_score")
    band = _esc(report.get("risk_band"))
    classification = report.get("classification", "")
    confidence = report.get("confidence")

    score_text = str(score) if score is not None else "N/A"
    color = _risk_color(score)

    score_data = [
        [
            Paragraph(f'<font color="{color.hexval()}">{_esc(score_text)}</font>', styles["score_big"]),
            Paragraph(f'<font color="{_classification_color(classification).hexval()}">{_esc(classification)}</font>', styles["badge"]),
        ],
        [
            Paragraph(f"Risk Band: {band}", styles["center"]),
            Paragraph(f"Confidence: {confidence}%" if confidence is not None else "Confidence: N/A", styles["center"]),
        ],
    ]
    t = Table(score_data, colWidths=[(PAGE_W - 2 * MARGIN) * 0.5] * 2)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, _LIGHT_BORDER),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, _LIGHT_BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), _BG_LIGHT),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 8))

    if report.get("summary"):
        elements.append(Paragraph(_esc(report["summary"]), styles["body"]))
    if report.get("explanation"):
        elements.append(Paragraph(_esc(report["explanation"]), styles["body"]))
    if report.get("recommendation"):
        elements.append(Paragraph(f"<b>Recommendation:</b> {_esc(report['recommendation'])}", styles["body"]))

    return elements


def _kv_table(pairs: list[tuple[str, str]], styles: dict) -> Table:
    data = []
    for label, value in pairs:
        data.append([
            Paragraph(f"<b>{_esc(label)}</b>", styles["table_cell"]),
            Paragraph(_esc(value), styles["table_cell"]),
        ])
    w = PAGE_W - 2 * MARGIN
    t = Table(data, colWidths=[w * 0.35, w * 0.65])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _url_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("URL Analysis", styles["h1"])]
    ua = report.get("url_analysis") or {}
    if ua.get("status") != "ok":
        elements.append(Paragraph(_esc(ua.get("message", "URL analysis unavailable.")), styles["body"]))
        return elements

    pairs = [
        ("Original URL", report.get("url", "")),
        ("Normalized URL", report.get("normalized_url", "")),
        ("Final URL", report.get("final_url", "")),
        ("Scheme", ua.get("scheme", "")),
        ("Hostname", ua.get("hostname", "")),
        ("Registered Domain", ua.get("registered_domain", "")),
        ("TLD", ua.get("tld", "")),
        ("URL Length", str(ua.get("url_length", ""))),
        ("Path Depth", str(ua.get("path_depth", ""))),
        ("Suspicious Keywords", ", ".join(ua.get("suspicious_keywords", [])) or "None"),
        ("IP Literal", "Yes" if ua.get("has_ip") else "No"),
        ("Punycode", "Yes" if ua.get("has_punycode") else "No"),
        ("URL Shortener", ua.get("shortener_service") or ("Yes" if ua.get("is_shortener") else "No")),
    ]
    elements.append(_kv_table(pairs, styles))
    return elements


def _domain_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Domain Analysis", styles["h1"])]
    da = report.get("domain_analysis") or {}
    if da.get("status") not in ("ok", "partial"):
        elements.append(Paragraph(_esc(da.get("message", "Domain analysis unavailable.")), styles["body"]))
        return elements

    reg = da.get("registration") or {}
    dns_info = da.get("dns") or {}
    pop = da.get("popularity") or {}
    rep = da.get("reputation") or {}

    pairs = [
        ("Domain", da.get("domain", "")),
        ("Registrar", reg.get("registrar") or "Unavailable"),
        ("Created", reg.get("created") or "Unavailable"),
        ("Domain Age (days)", str(reg.get("domain_age_days")) if reg.get("domain_age_days") is not None else "Unavailable"),
        ("Expires", reg.get("expires") or "Unavailable"),
        ("DNS Resolves", "Yes" if dns_info.get("resolves") else "No"),
        ("MX Records", str(len(dns_info.get("mx", [])))),
        ("SPF", "Yes" if dns_info.get("has_spf") else ("No" if dns_info.get("has_spf") is False else "Unknown")),
        ("DMARC", "Yes" if dns_info.get("has_dmarc") else ("No" if dns_info.get("has_dmarc") is False else "Unknown")),
        ("Popularity", f"Rank {pop['rank']} ({pop.get('source', '')})" if pop.get("rank") else pop.get("message", "Not available")),
        ("Reputation", f"Listed: {', '.join(rep.get('threats', []))}" if rep.get("listed") else (rep.get("message", "Not configured"))),
    ]
    asn = da.get("asn")
    if asn:
        pairs.append(("ASN", f"AS{asn.get('asn', '')} - {asn.get('as_name', '')} ({asn.get('country', '')})"))

    elements.append(_kv_table(pairs, styles))
    return elements


def _tls_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("TLS / Certificate Analysis", styles["h1"])]
    ta = report.get("tls_analysis") or {}
    if ta.get("status") not in ("ok",):
        elements.append(Paragraph(_esc(ta.get("message", "TLS analysis unavailable.")), styles["body"]))
        return elements

    subject = ta.get("subject") or {}
    issuer = ta.get("issuer") or {}
    pairs = [
        ("HTTPS Available", "Yes" if ta.get("https_available") else "No"),
        ("Certificate Valid", "Yes" if ta.get("certificate_valid") else "No"),
        ("Hostname Match", "Yes" if ta.get("hostname_match") else ("No" if ta.get("hostname_match") is False else "Unknown")),
        ("Subject CN", subject.get("common_name") or "N/A"),
        ("Issuer", f"{issuer.get('organization', '')} ({issuer.get('common_name', '')})"),
        ("Not Before", ta.get("not_before") or "N/A"),
        ("Not After", ta.get("not_after") or "N/A"),
        ("Days Until Expiry", str(ta.get("days_until_expiry")) if ta.get("days_until_expiry") is not None else "N/A"),
        ("TLS Version", ta.get("tls_version") or "N/A"),
        ("Cipher", ta.get("cipher") or "N/A"),
        ("Self-Signed", "Yes" if ta.get("self_signed") else "No"),
        ("Issuer Category", ta.get("issuer_category") or "N/A"),
    ]
    elements.append(_kv_table(pairs, styles))
    if ta.get("note"):
        elements.append(Paragraph(f"<i>{_esc(ta['note'])}</i>", styles["small"]))
    return elements


def _redirect_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Redirect Analysis", styles["h1"])]
    ra = report.get("redirect_analysis") or {}
    if ra.get("status") not in ("ok",):
        elements.append(Paragraph(_esc(ra.get("message", "Redirect analysis unavailable.")), styles["body"]))
        return elements

    pairs = [
        ("Number of Redirects", str(ra.get("num_redirects", 0))),
        ("Cross-Domain", "Yes" if ra.get("crossed_domains") else "No"),
        ("Distinct Domains", str(ra.get("distinct_domains", 0))),
        ("HTTPS Downgrade", "Yes" if ra.get("https_downgrade") else "No"),
        ("Final URL", ra.get("final_url") or "N/A"),
    ]
    elements.append(_kv_table(pairs, styles))

    chain = ra.get("chain") or []
    if chain:
        elements.append(Paragraph("Redirect Chain", styles["h2"]))
        header = [
            Paragraph("URL", styles["table_header"]),
            Paragraph("Status", styles["table_header"]),
            Paragraph("Host", styles["table_header"]),
        ]
        data = [header]
        for hop in chain[:15]:
            data.append([
                Paragraph(_esc(str(hop.get("url", ""))[:80]), styles["table_cell"]),
                Paragraph(str(hop.get("status_code", "")), styles["table_cell"]),
                Paragraph(_esc(str(hop.get("host", ""))), styles["table_cell"]),
            ])
        w = PAGE_W - 2 * MARGIN
        t = Table(data, colWidths=[w * 0.55, w * 0.12, w * 0.33])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)
    return elements


def _webpage_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Webpage Analysis", styles["h1"])]
    wa = report.get("webpage_analysis") or {}
    if wa.get("status") not in ("ok", "restricted"):
        elements.append(Paragraph(_esc(wa.get("message", "Webpage analysis unavailable.")), styles["body"]))
        return elements

    if wa.get("status") == "restricted":
        elements.append(Paragraph(f"Access restricted: {_esc(wa.get('message', ''))}", styles["body"]))

    forms = wa.get("forms") or {}
    links = wa.get("links") or {}
    pairs = [
        ("Title", wa.get("title") or "None"),
        ("HTTP Status", str(wa.get("http_status", ""))),
        ("Content Type", wa.get("content_type") or "N/A"),
        ("Forms", str(forms.get("count", 0))),
        ("Password Fields", str(forms.get("with_password", 0))),
        ("Login Form", "Yes" if forms.get("login_form") else "No"),
        ("External Form Actions", str(forms.get("external_action_count", 0))),
        ("Total Links", str(links.get("total", 0))),
        ("External Links", str(links.get("external", 0))),
        ("Login Wording", "Yes" if wa.get("has_login_wording") else "No"),
        ("Hidden Elements", str(wa.get("hidden_elements", 0))),
    ]
    iframes = wa.get("iframes") or {}
    if iframes.get("count", 0) > 0:
        pairs.append(("Iframes", f"{iframes['count']} (hidden: {iframes.get('hidden', 0)})"))

    elements.append(_kv_table(pairs, styles))
    return elements


def _brand_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Brand Detection", styles["h1"])]
    ba = report.get("brand_analysis") or {}
    if ba.get("status") != "ok":
        elements.append(Paragraph(_esc(ba.get("message", "Brand analysis unavailable.")), styles["body"]))
        return elements

    brands = ba.get("brands_detected") or []
    if not brands:
        elements.append(Paragraph("No known brands detected.", styles["body"]))
    else:
        for b in brands[:10]:
            official = "Yes" if b.get("domain_matches_official") else "No"
            sources_str = ", ".join(b.get("sources", []))
            elements.append(Paragraph(
                f"<b>{_esc(b.get('display_name', b.get('brand', '')))}</b> "
                f"- Official domain: {official} | Sources: {_esc(sources_str)}",
                styles["body"],
            ))

    if ba.get("impersonation_suspected"):
        elements.append(Paragraph(
            f"<font color='{_DANGER.hexval()}'><b>Impersonation suspected:</b> {_esc(ba.get('explanation', ''))}</font>",
            styles["body"],
        ))

    typo = ba.get("typosquat") or {}
    if typo.get("detected"):
        elements.append(Paragraph(
            f"<b>Typosquat detected:</b> {_esc(typo.get('brand', ''))} "
            f"(technique: {_esc(typo.get('technique', ''))}, similarity: {typo.get('similarity', '')})",
            styles["body"],
        ))

    return elements


def _ml_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("ML Model Analysis", styles["h1"])]
    ml = report.get("ml_analysis") or {}
    if ml.get("status") != "ok":
        elements.append(Paragraph(_esc(ml.get("message", "ML model unavailable.")), styles["body"]))
        return elements

    prob_ph = ml.get("probability_phishing")
    prob_le = ml.get("probability_legitimate")
    pairs = [
        ("Model", f"{ml.get('model_name', 'N/A')} v{ml.get('model_version', 'N/A')}"),
        ("P(Phishing)", f"{prob_ph:.3f}" if prob_ph is not None else "N/A"),
        ("P(Legitimate)", f"{prob_le:.3f}" if prob_le is not None else "N/A"),
        ("ML Verdict", ml.get("ml_verdict") or "N/A"),
        ("Feature Set", ml.get("feature_set") or "N/A"),
    ]
    elements.append(_kv_table(pairs, styles))

    top_f = ml.get("top_features") or []
    if top_f:
        elements.append(Paragraph("Top Features", styles["h2"]))
        header = [
            Paragraph("Feature", styles["table_header"]),
            Paragraph("Value", styles["table_header"]),
            Paragraph("Importance", styles["table_header"]),
        ]
        data = [header]
        for feat in top_f[:6]:
            data.append([
                Paragraph(_esc(str(feat.get("feature", ""))), styles["table_cell"]),
                Paragraph(str(feat.get("value", "")), styles["table_cell"]),
                Paragraph(f"{feat.get('importance', 0):.4f}", styles["table_cell"]),
            ])
        w = PAGE_W - 2 * MARGIN
        t = Table(data, colWidths=[w * 0.45, w * 0.25, w * 0.30])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(t)

    if ml.get("note"):
        elements.append(Paragraph(f"<i>{_esc(ml['note'])}</i>", styles["small"]))
    return elements


def _findings_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("All Findings", styles["h1"])]
    indicators = report.get("indicators") or []
    if not indicators:
        elements.append(Paragraph("No findings recorded.", styles["body"]))
        return elements

    header = [
        Paragraph("Severity", styles["table_header"]),
        Paragraph("Category", styles["table_header"]),
        Paragraph("Finding", styles["table_header"]),
        Paragraph("Points", styles["table_header"]),
    ]
    data = [header]
    for f in indicators[:_MAX_TABLE_ROWS]:
        sev = f.get("severity", "info")
        sev_color = _severity_color(sev)
        data.append([
            Paragraph(f"<font color='{sev_color.hexval()}'>{_esc(sev)}</font>", styles["table_cell"]),
            Paragraph(_esc(f.get("category", "")), styles["table_cell"]),
            Paragraph(_esc(f.get("message", "")), styles["table_cell"]),
            Paragraph(f"{f.get('points', 0):+.0f}", styles["table_cell"]),
        ])

    w = PAGE_W - 2 * MARGIN
    t = Table(data, colWidths=[w * 0.12, w * 0.12, w * 0.62, w * 0.14])
    row_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            row_styles.append(("BACKGROUND", (0, i), (-1, i), _BG_LIGHT))
    t.setStyle(TableStyle(row_styles))
    elements.append(t)

    if len(indicators) > _MAX_TABLE_ROWS:
        elements.append(Paragraph(
            f"... and {len(indicators) - _MAX_TABLE_ROWS} more finding(s) not shown.",
            styles["small"],
        ))
    return elements


def _category_scores_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Category Scores", styles["h1"])]
    cats = report.get("category_scores") or []
    if not cats:
        elements.append(Paragraph("No category scores available.", styles["body"]))
        return elements

    header = [
        Paragraph("Category", styles["table_header"]),
        Paragraph("Risk Score", styles["table_header"]),
        Paragraph("Status", styles["table_header"]),
    ]
    data = [header]
    for cat in cats:
        risk_val = cat.get("risk")
        risk_str = str(risk_val) if risk_val is not None else "N/A"
        color = _risk_color(risk_val)
        data.append([
            Paragraph(_esc(cat.get("label", "")), styles["table_cell"]),
            Paragraph(f"<font color='{color.hexval()}'>{risk_str}</font>", styles["table_cell"]),
            Paragraph(_esc(cat.get("status", "")), styles["table_cell"]),
        ])

    w = PAGE_W - 2 * MARGIN
    t = Table(data, colWidths=[w * 0.40, w * 0.30, w * 0.30])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t)
    return elements


def _scoring_section(report: dict, styles: dict) -> list:
    elements = [Paragraph("Scoring Breakdown", styles["h1"])]
    scoring = report.get("scoring") or {}
    components = scoring.get("components") or {}
    if not components:
        elements.append(Paragraph("No scoring breakdown available.", styles["body"]))
        return elements

    header = [
        Paragraph("Component", styles["table_header"]),
        Paragraph("Score", styles["table_header"]),
        Paragraph("Weight", styles["table_header"]),
        Paragraph("Available", styles["table_header"]),
        Paragraph("Detail", styles["table_header"]),
    ]
    data = [header]
    weights_eff = scoring.get("weights_effective") or {}
    for name, comp in components.items():
        data.append([
            Paragraph(_esc(name.upper()), styles["table_cell"]),
            Paragraph(str(comp.get("score", "N/A")), styles["table_cell"]),
            Paragraph(f"{weights_eff.get(name, 0):.1%}", styles["table_cell"]),
            Paragraph("Yes" if comp.get("available") else "No", styles["table_cell"]),
            Paragraph(_esc(comp.get("detail", "")), styles["table_cell"]),
        ])

    w = PAGE_W - 2 * MARGIN
    t = Table(data, colWidths=[w * 0.15, w * 0.10, w * 0.12, w * 0.13, w * 0.50])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _LIGHT_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t)

    if scoring.get("floor_applied") is not None:
        elements.append(Paragraph(
            f"<b>Floor applied:</b> {scoring['floor_applied']} - {_esc(scoring.get('floor_reason', ''))}",
            styles["body"],
        ))

    elements.append(Paragraph(f"<i>Method: {_esc(scoring.get('method', ''))}</i>", styles["small"]))
    return elements


def generate_pdf(report: dict, output_path: str) -> str:
    styles = _build_styles()
    elements: list = []

    elements.append(Spacer(1, 30 * mm))

    scan_id = report.get("scan_id", "")
    created = report.get("created_at", "")
    status = report.get("status", "")
    elements.append(Paragraph(f"Scan Report: {_esc(scan_id)}", styles["title"]))
    meta_parts = []
    if created:
        meta_parts.append(f"Date: {_esc(created)}")
    meta_parts.append(f"Status: {_esc(status)}")
    duration = report.get("duration_ms")
    if duration is not None:
        meta_parts.append(f"Duration: {duration}ms")
    elements.append(Paragraph(" | ".join(meta_parts), styles["small"]))
    elements.append(Spacer(1, 6))

    if report.get("error"):
        err = report["error"]
        elements.append(Paragraph(
            f"<font color='{_DANGER.hexval()}'><b>Error:</b> [{_esc(err.get('code', ''))}] {_esc(err.get('message', ''))}</font>",
            styles["body"],
        ))

    for notice in (report.get("notices") or []):
        elements.append(Paragraph(f"<i>Notice: {_esc(notice)}</i>", styles["body"]))

    elements.extend(_score_section(report, styles))
    elements.extend(_category_scores_section(report, styles))
    elements.extend(_url_section(report, styles))
    elements.extend(_redirect_section(report, styles))
    elements.extend(_domain_section(report, styles))
    elements.extend(_tls_section(report, styles))
    elements.extend(_webpage_section(report, styles))
    elements.extend(_brand_section(report, styles))
    elements.extend(_ml_section(report, styles))
    elements.extend(_scoring_section(report, styles))
    elements.extend(_findings_section(report, styles))

    elements.append(Spacer(1, 12))
    disclaimer = report.get(
        "disclaimer",
        "This automated assessment is based on available technical signals and should not be treated as "
        "definitive proof of website legitimacy or maliciousness.",
    )
    elements.append(Paragraph(_esc(disclaimer), styles["disclaimer"]))

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=32 * mm,
        bottomMargin=18 * mm,
        title=f"PhishGuard Report - {_esc(scan_id)}",
        author="PhishGuard",
    )
    doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path
