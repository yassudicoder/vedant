"""
Shared primitives used by every analyzer.

A *finding* is one explainable observation produced by an analyzer or by the
rule engine. Findings are plain dicts so they serialise directly to JSON:

    {
        "id":       "url.ip_host",          # stable, dotted identifier
        "severity": "strong",               # strong | medium | low | positive | info
        "category": "url",                  # see CATEGORIES
        "message":  "URL uses a raw IP address instead of a domain name.",
        "detail":   "Host: 203.0.113.7",    # optional supporting evidence (or None)
        "points":   22.0,                   # risk points (+ raises risk, - lowers risk)
        "source":   "url_analyzer",         # module that produced it
    }

Point guidelines (the risk engine saturates component sums, see risk_engine):
    strong   +20 .. +35    medium  +10 .. +18    low  +3 .. +8
    positive  -3 .. -15    info      0
"""
from __future__ import annotations

from typing import Any, Literal

Severity = Literal["strong", "medium", "low", "positive", "info"]

SEVERITIES: tuple[str, ...] = ("strong", "medium", "low", "positive", "info")

CATEGORIES: tuple[str, ...] = (
    "url",          # lexical URL features
    "redirect",     # redirect chain / meta refresh / JS redirects
    "domain",       # registration, DNS, ASN, popularity
    "tls",          # HTTPS / certificate
    "webpage",      # HTML structure, forms, links, scripts
    "brand",        # brand impersonation / typosquatting
    "reputation",   # optional external reputation (e.g. Google Safe Browsing)
    "ml",           # machine-learning model
    "rule",         # cross-signal combination rules (rule engine)
)

DEFAULT_POINTS: dict[str, float] = {
    "strong": 25.0,
    "medium": 12.0,
    "low": 5.0,
    "positive": -6.0,
    "info": 0.0,
}

UNAVAILABLE = "Unavailable"


def make_finding(
    finding_id: str,
    severity: Severity,
    category: str,
    message: str,
    *,
    detail: str | None = None,
    points: float | None = None,
    source: str = "",
) -> dict[str, Any]:
    """Build a finding dict with validated severity/category."""
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    if category not in CATEGORIES:
        raise ValueError(f"invalid category: {category}")
    if points is None:
        points = DEFAULT_POINTS[severity]
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "message": message,
        "detail": detail,
        "points": float(points),
        "source": source,
    }


def truncate(text: str | None, limit: int = 300) -> str | None:
    """Trim untrusted page text before it is stored or returned."""
    if text is None:
        return None
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
