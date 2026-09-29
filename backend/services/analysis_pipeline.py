"""
Analysis pipeline: orchestrates URL validation, fetching, all analyzers, the
rule engine and risk engine into a single report dict.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from backend.config import settings
from backend.security.ssrf_protection import (
    BlockedDestinationError,
    FetchError,
    FetchResult,
    resolve_and_validate,
    safe_fetch,
)
from backend.security.validation import (
    NormalizedURL,
    URLValidationError,
    normalize_url,
    redact_url,
)
from backend.services.brand_detector import analyze_brand
from backend.services.common import truncate
from backend.services.domain_analyzer import analyze_domain
from backend.services.ml_detector import predict as ml_predict
from backend.services.redirect_analyzer import analyze_redirects
from backend.services.risk_engine import compute_risk
from backend.services.rule_engine import evaluate_rules
from backend.services.tls_analyzer import analyze_tls
from backend.services.url_analyzer import analyze_url
from backend.services.webpage_analyzer import analyze_webpage

log = logging.getLogger(__name__)

STAGES: list[tuple[str, str]] = [
    ("validate", "Analyzing URL..."),
    ("dns", "Checking domain..."),
    ("https", "Checking HTTPS..."),
    ("redirects", "Following safe redirects..."),
    ("webpage", "Analyzing webpage structure..."),
    ("features", "Extracting security features..."),
    ("model", "Running detection model..."),
    ("report", "Generating report..."),
]

_UNAVAILABLE = {"status": "unavailable", "message": "Unavailable", "findings": []}


def _emit(progress: Callable[[str, str], None] | None, stage: str, state: str) -> None:
    if progress:
        try:
            progress(stage, state)
        except Exception:
            pass


def _deadline_remaining(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.1)


def _redact_chain(chain: list[dict]) -> list[dict]:
    out = []
    for hop in chain:
        h = dict(hop)
        if "url" in h:
            h["url"] = redact_url(h["url"])
        if "location" in h and h["location"]:
            h["location"] = redact_url(h["location"])
        out.append(h)
    return out


def _redact_report(report: dict) -> dict:
    for key in ("url", "normalized_url", "final_url"):
        if key in report and isinstance(report[key], str):
            report[key] = redact_url(report[key])

    redir = report.get("redirect_analysis")
    if isinstance(redir, dict):
        if "chain" in redir:
            redir["chain"] = _redact_chain(redir.get("chain") or [])
        if "final_url" in redir and isinstance(redir["final_url"], str):
            redir["final_url"] = redact_url(redir["final_url"])

    url_a = report.get("url_analysis")
    if isinstance(url_a, dict):
        for field in ("path", "query", "fragment"):
            if field in url_a and isinstance(url_a[field], str) and url_a[field]:
                pass

    return report


def run_analysis(raw_url: str, progress: Callable[[str, str], None] | None = None) -> dict:
    deadline = time.monotonic() + settings.SCAN_TOTAL_TIMEOUT
    start_ms = time.monotonic()
    notices: list[str] = []

    _emit(progress, "validate", "started")
    nurl = normalize_url(raw_url)
    _emit(progress, "validate", "done")

    url_analysis = analyze_url(nurl)

    _emit(progress, "dns", "started")
    resolved_ips: list[str] | None = None
    try:
        resolved_ips = resolve_and_validate(nurl.hostname, nurl.effective_port)
    except BlockedDestinationError:
        _emit(progress, "dns", "done")
        elapsed = round((time.monotonic() - start_ms) * 1000)
        return _redact_report({
            "url": nurl.original,
            "normalized_url": nurl.normalized,
            "final_url": nurl.normalized,
            "status": "failed",
            "classification": "ANALYSIS_FAILED",
            "risk_score": None,
            "risk_band": None,
            "confidence": None,
            "summary": None,
            "explanation": None,
            "recommendation": None,
            "error": {"code": "BLOCKED_DESTINATION", "message": "This destination resolves to a restricted network address."},
            "notices": [],
            "duration_ms": elapsed,
            "url_analysis": url_analysis,
            "domain_analysis": _UNAVAILABLE.copy(),
            "tls_analysis": _UNAVAILABLE.copy(),
            "redirect_analysis": _UNAVAILABLE.copy(),
            "webpage_analysis": _UNAVAILABLE.copy(),
            "brand_analysis": _UNAVAILABLE.copy(),
            "ml_analysis": _UNAVAILABLE.copy(),
            "rule_analysis": _UNAVAILABLE.copy(),
            "scoring": None,
            "category_scores": [],
            "indicators": [],
            "indicator_groups": {},
            "disclaimer": "This automated assessment is based on available technical signals and should not be treated as definitive proof of website legitimacy or maliciousness.",
        })
    except FetchError as exc:
        if exc.code == "DNS_FAILURE":
            _emit(progress, "dns", "done")
            elapsed = round((time.monotonic() - start_ms) * 1000)
            return _redact_report({
                "url": nurl.original,
                "normalized_url": nurl.normalized,
                "final_url": nurl.normalized,
                "status": "failed",
                "classification": "ANALYSIS_FAILED",
                "risk_score": None,
                "risk_band": None,
                "confidence": None,
                "summary": None,
                "explanation": None,
                "recommendation": None,
                "error": {"code": "DNS_FAILURE", "message": "The domain name could not be resolved."},
                "notices": [],
                "duration_ms": elapsed,
                "url_analysis": url_analysis,
                "domain_analysis": _UNAVAILABLE.copy(),
                "tls_analysis": _UNAVAILABLE.copy(),
                "redirect_analysis": _UNAVAILABLE.copy(),
                "webpage_analysis": _UNAVAILABLE.copy(),
                "brand_analysis": _UNAVAILABLE.copy(),
                "ml_analysis": _UNAVAILABLE.copy(),
                "rule_analysis": _UNAVAILABLE.copy(),
                "scoring": None,
                "category_scores": [],
                "indicators": [],
                "indicator_groups": {},
                "disclaimer": "This automated assessment is based on available technical signals and should not be treated as definitive proof of website legitimacy or maliciousness.",
            })
        resolved_ips = None
    _emit(progress, "dns", "done")

    domain_future = None
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        domain_future = executor.submit(
            analyze_domain, nurl.hostname, resolved_ips=resolved_ips
        )

        _emit(progress, "https", "started")
        tls_analysis: dict[str, Any] = _UNAVAILABLE.copy()
        if nurl.scheme == "https" or nurl.scheme_assumed:
            try:
                tls_analysis = analyze_tls(
                    nurl.hostname,
                    nurl.effective_port if nurl.scheme == "https" else 443,
                    https_requested=(nurl.scheme == "https"),
                )
            except Exception:
                log.exception("TLS analysis failed")
                tls_analysis = {"status": "error", "message": "TLS analysis failed.", "findings": []}
        _emit(progress, "https", "done")

        _emit(progress, "redirects", "started")
        fetch: FetchResult | None = None
        fetch_error: FetchError | None = None
        ssl_error_occurred = False

        try:
            fetch = safe_fetch(
                nurl.normalized,
                max_redirects=settings.FETCH_MAX_REDIRECTS,
                timeout=min(settings.FETCH_TOTAL_TIMEOUT, _deadline_remaining(deadline)),
            )
        except FetchError as exc:
            fetch_error = exc
            if exc.code == "SSL_ERROR":
                ssl_error_occurred = True
                if tls_analysis.get("status") == "unavailable":
                    try:
                        tls_analysis = analyze_tls(
                            nurl.hostname,
                            nurl.effective_port if nurl.scheme == "https" else 443,
                            https_requested=True,
                        )
                    except Exception:
                        pass
                try:
                    fetch = safe_fetch(
                        nurl.normalized,
                        max_redirects=settings.FETCH_MAX_REDIRECTS,
                        verify_tls=False,
                        timeout=min(settings.FETCH_TOTAL_TIMEOUT, _deadline_remaining(deadline)),
                    )
                    notices.append("TLS certificate verification failed; page was fetched without verification for analysis only.")
                except FetchError as inner_exc:
                    fetch_error = inner_exc
            elif exc.code == "TIMEOUT":
                notices.append("Website did not respond within the allowed time.")
            elif nurl.scheme_assumed and exc.code in ("CONNECTION_FAILED", "TIMEOUT"):
                http_url = nurl.normalized.replace("https://", "http://", 1)
                try:
                    fetch = safe_fetch(
                        http_url,
                        max_redirects=settings.FETCH_MAX_REDIRECTS,
                        timeout=min(settings.FETCH_TOTAL_TIMEOUT, _deadline_remaining(deadline)),
                    )
                    notices.append("HTTPS connection failed; fell back to HTTP.")
                except FetchError:
                    pass
        except Exception:
            log.exception("Unexpected fetch error")

        http_probe: bool | None = None
        _emit(progress, "redirects", "done")

        _emit(progress, "webpage", "started")
        webpage_analysis: dict[str, Any]
        page_url = fetch.final_url if fetch else nurl.normalized
        try:
            webpage_analysis = analyze_webpage(fetch, page_url=page_url, fetch_error=fetch_error)
        except Exception:
            log.exception("Webpage analysis failed")
            webpage_analysis = {"status": "error", "message": "Webpage analysis failed.", "findings": []}
        _emit(progress, "webpage", "done")

        redirect_analysis: dict[str, Any]
        try:
            redirect_analysis = analyze_redirects(
                nurl, fetch,
                http_probe=http_probe,
                page_signals=webpage_analysis if webpage_analysis.get("status") == "ok" else None,
            )
        except Exception:
            log.exception("Redirect analysis failed")
            redirect_analysis = {"status": "error", "message": "Redirect analysis failed.", "findings": []}

        domain_analysis: dict[str, Any] = _UNAVAILABLE.copy()
        if domain_future is not None:
            try:
                remaining = _deadline_remaining(deadline)
                domain_analysis = domain_future.result(timeout=remaining)
            except Exception:
                log.exception("Domain analysis failed")
                domain_analysis = {"status": "error", "message": "Domain analysis failed.", "findings": []}
    finally:
        executor.shutdown(wait=False)

    _emit(progress, "features", "started")
    final_registered_domain = redirect_analysis.get("final_registered_domain")
    if not final_registered_domain:
        final_registered_domain = url_analysis.get("registered_domain")

    brand_analysis: dict[str, Any]
    try:
        brand_analysis = analyze_brand(
            url_analysis,
            webpage_analysis if webpage_analysis.get("status") == "ok" else None,
            final_registered_domain,
        )
    except Exception:
        log.exception("Brand analysis failed")
        brand_analysis = {"status": "error", "message": "Brand analysis failed.", "findings": []}
    _emit(progress, "features", "done")

    _emit(progress, "model", "started")
    ml_analysis: dict[str, Any]
    ml_features = url_analysis.get("ml_features")
    if ml_features:
        try:
            ml_analysis = ml_predict(ml_features)
        except Exception:
            log.exception("ML prediction failed")
            ml_analysis = {"status": "unavailable", "message": "ML prediction failed.", "findings": []}
    else:
        ml_analysis = {"status": "unavailable", "message": "ML features not available.", "findings": []}
    _emit(progress, "model", "done")

    _emit(progress, "report", "started")
    ctx = {
        "url": url_analysis,
        "domain": domain_analysis,
        "tls": tls_analysis,
        "redirect": redirect_analysis,
        "webpage": webpage_analysis,
        "brand": brand_analysis,
        "ml": ml_analysis,
    }

    rule_result = evaluate_rules(ctx)
    risk_result = compute_risk(ctx, rule_result)

    final_url = nurl.normalized
    if fetch:
        final_url = fetch.final_url
    elif redirect_analysis.get("final_url"):
        final_url = redirect_analysis["final_url"]

    status = "completed"
    if fetch is None and fetch_error is not None:
        status = "partial"

    elapsed = round((time.monotonic() - start_ms) * 1000)

    report: dict[str, Any] = {
        "url": nurl.original,
        "normalized_url": nurl.normalized,
        "final_url": final_url,
        "status": status,
        "classification": risk_result["classification"],
        "risk_score": risk_result["risk_score"],
        "risk_band": risk_result["risk_band"],
        "confidence": risk_result["confidence"],
        "summary": risk_result["summary"],
        "explanation": risk_result["explanation"],
        "recommendation": risk_result["recommendation"],
        "error": None,
        "notices": notices,
        "duration_ms": elapsed,
        "url_analysis": url_analysis,
        "domain_analysis": domain_analysis,
        "tls_analysis": tls_analysis,
        "redirect_analysis": redirect_analysis,
        "webpage_analysis": webpage_analysis,
        "brand_analysis": brand_analysis,
        "ml_analysis": ml_analysis,
        "rule_analysis": rule_result,
        "scoring": {
            "components": risk_result["components"],
            "weights_effective": risk_result["weights_effective"],
            "floor_applied": risk_result["floor_applied"],
            "floor_reason": risk_result["floor_reason"],
            "band_thresholds": risk_result["band_thresholds"],
            "method": risk_result["method"],
        },
        "category_scores": risk_result["category_scores"],
        "indicators": risk_result["indicators"],
        "indicator_groups": risk_result["indicator_groups"],
        "disclaimer": "This automated assessment is based on available technical signals and should not be treated as definitive proof of website legitimacy or maliciousness.",
    }
    _emit(progress, "report", "done")

    return _redact_report(report)
