"""Redirect chain analysis for PhishGuard."""
from __future__ import annotations

from urllib.parse import urlsplit

from backend.services.common import make_finding, truncate, UNAVAILABLE
from backend.security.validation import NormalizedURL
from backend.security.ssrf_protection import FetchResult
from ml.feature_extractor import parse_host, hostname_from_url

SOURCE = "redirect_analyzer"

KNOWN_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "j.mp", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "v.gd", "ow.ly", "rebrand.ly", "rb.gy", "cutt.ly",
    "shorturl.at", "shorturl.asia", "tiny.cc", "lnkd.in", "buff.ly",
    "adf.ly", "bl.ink", "surl.li", "qr.ae", "amzn.to", "youtu.be",
    "fb.me", "bit.do", "shorte.st", "clck.ru", "mcaf.ee", "u.to",
    "dub.sh", "t.ly", "short.io", "han.gl", "reduced.to", "trib.al",
})


def _host_from_url(url: str) -> str:
    return hostname_from_url(url) or ""


def _rd_from_url(url: str) -> str:
    host = _host_from_url(url)
    if not host:
        return ""
    return parse_host(host).registered_domain


def _scheme_of(url: str) -> str:
    try:
        return urlsplit(url).scheme.lower()
    except Exception:
        return ""


def _unavailable_result(
    message: str,
    http_probe: bool | None,
) -> dict:
    return {
        "status": "unavailable",
        "message": message,
        "num_redirects": 0,
        "chain": [],
        "final_url": None,
        "final_host": None,
        "final_registered_domain": None,
        "crossed_domains": False,
        "distinct_domains": 0,
        "https_downgrade": False,
        "upgraded_to_https": False,
        "http_redirects_to_https": http_probe,
        "meta_refresh": None,
        "js_redirect_detected": False,
        "shortener_expanded": False,
        "findings": [],
    }


def analyze_redirects(
    requested: NormalizedURL,
    fetch: FetchResult | None,
    *,
    http_probe: bool | None,
    page_signals: dict | None,
) -> dict:
    if fetch is None:
        return _unavailable_result(
            "No fetch result available for redirect analysis.", http_probe
        )

    chain = fetch.redirect_chain
    requested_rd = parse_host(requested.hostname).registered_domain

    built_chain: list[dict] = []
    domains_seen: set[str] = {requested_rd} if requested_rd else set()
    has_https_downgrade = False
    has_upgrade = False
    prev_scheme = requested.scheme

    for hop in chain:
        hop_host = _host_from_url(hop.url)
        hop_rd = parse_host(hop_host).registered_domain if hop_host else ""
        cross = bool(hop_rd and hop_rd != requested_rd)
        if hop_rd:
            domains_seen.add(hop_rd)

        hop_scheme = _scheme_of(hop.url)
        if prev_scheme == "https" and hop_scheme == "http":
            has_https_downgrade = True
        if prev_scheme == "http" and hop_scheme == "https":
            has_upgrade = True
        if hop_scheme:
            prev_scheme = hop_scheme

        built_chain.append({
            "url": truncate(hop.url, 500),
            "status_code": hop.status_code,
            "host": hop_host,
            "registered_domain": hop_rd,
            "cross_domain": cross,
        })

    final_url = fetch.final_url
    final_host = _host_from_url(final_url)
    final_rd = parse_host(final_host).registered_domain if final_host else ""
    if final_rd:
        domains_seen.add(final_rd)

    final_scheme = _scheme_of(final_url)
    if chain:
        if prev_scheme == "https" and final_scheme == "http":
            has_https_downgrade = True
        if prev_scheme == "http" and final_scheme == "https":
            has_upgrade = True

    crossed_domains = (
        any(h["cross_domain"] for h in built_chain)
        or bool(final_rd and final_rd != requested_rd)
    )
    distinct_domains = len(domains_seen)

    requested_is_shortener = (
        requested.hostname in KNOWN_SHORTENER_DOMAINS
        or parse_host(requested.hostname).registered_domain in KNOWN_SHORTENER_DOMAINS
    )
    shortener_expanded = (
        requested_is_shortener
        and final_rd != requested_rd
        and len(chain) > 0
    )

    meta_refresh = None
    js_redirect_detected = False
    if page_signals:
        meta_refresh = page_signals.get("meta_refresh")
        js_redirect_detected = bool(page_signals.get("js_redirect"))

    num_redirects = len(chain)

    # --- Findings ---
    findings: list[dict] = []

    if num_redirects > 3:
        findings.append(make_finding(
            "redirect.excessive", "medium", "redirect",
            f"URL follows {num_redirects} redirects before reaching the final destination.",
            detail=f"Redirect count: {num_redirects}",
            points=12, source=SOURCE,
        ))
    elif num_redirects > 1:
        findings.append(make_finding(
            "redirect.multiple", "low", "redirect",
            f"URL follows {num_redirects} redirects.",
            detail=f"Redirect count: {num_redirects}",
            points=3, source=SOURCE,
        ))

    if crossed_domains:
        findings.append(make_finding(
            "redirect.cross_domain", "medium", "redirect",
            f"Redirects cross domain boundaries ({distinct_domains} distinct domains).",
            detail=f"Domains: {', '.join(sorted(domains_seen)[:5])}",
            points=14, source=SOURCE,
        ))

    if has_https_downgrade:
        findings.append(make_finding(
            "redirect.https_downgrade", "strong", "redirect",
            "Redirect chain downgrades from HTTPS to HTTP, exposing data in transit.",
            points=20, source=SOURCE,
        ))

    if shortener_expanded:
        findings.append(make_finding(
            "redirect.shortener_expanded", "low", "redirect",
            f"Link shortener expanded to a different domain ({final_rd}).",
            detail=f"Shortener: {requested.hostname} -> Final: {final_rd}",
            points=4, source=SOURCE,
        ))

    if meta_refresh:
        mr_url = truncate(meta_refresh.get("url", ""), 200)
        mr_delay = meta_refresh.get("delay", "?")
        findings.append(make_finding(
            "redirect.meta_refresh", "low", "redirect",
            "Page uses a meta-refresh tag to redirect the browser.",
            detail=f"Target: {mr_url}, Delay: {mr_delay}s",
            points=5, source=SOURCE,
        ))

    if js_redirect_detected:
        findings.append(make_finding(
            "redirect.js_redirect", "low", "redirect",
            "Page uses JavaScript to redirect the browser.",
            points=5, source=SOURCE,
        ))

    return {
        "status": "ok",
        "num_redirects": num_redirects,
        "chain": built_chain,
        "final_url": truncate(final_url, 500),
        "final_host": final_host,
        "final_registered_domain": final_rd,
        "crossed_domains": crossed_domains,
        "distinct_domains": distinct_domains,
        "https_downgrade": has_https_downgrade,
        "upgraded_to_https": has_upgrade,
        "http_redirects_to_https": http_probe,
        "meta_refresh": meta_refresh,
        "js_redirect_detected": js_redirect_detected,
        "shortener_expanded": shortener_expanded,
        "findings": findings,
    }
