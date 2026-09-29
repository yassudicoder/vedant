"""
Risk engine: combines ML, rule, webpage and domain component scores into a
single 0-100 risk score with classification and confidence.
"""
from __future__ import annotations

import math
from typing import Any

from backend.config import settings
from backend.services.common import SEVERITIES


def saturate(raw_points: float) -> float:
    return 100.0 * (1.0 - math.exp(-max(raw_points, 0.0) / 45.0))


def _sum_points(findings: list[dict], categories: set[str]) -> tuple[float, float]:
    positive = 0.0
    negative = 0.0
    for f in findings:
        if f.get("category") not in categories:
            continue
        pts = f.get("points", 0.0)
        if pts > 0:
            positive += pts
        else:
            negative += abs(pts)
    return positive, negative


def _component_score(positive: float, negative: float) -> float:
    return max(saturate(positive) - negative, 0.0)


def _all_findings(ctx: dict, rule_result: dict) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()
    for key in ("url", "redirect", "domain", "tls", "webpage", "brand", "ml"):
        section = ctx.get(key)
        if isinstance(section, dict):
            for f in section.get("findings", []):
                fid = f.get("id", "")
                if fid not in seen:
                    seen.add(fid)
                    findings.append(f)
    for f in rule_result.get("findings", []):
        fid = f.get("id", "")
        if fid not in seen:
            seen.add(fid)
            findings.append(f)
    return findings


def _severity_order(sev: str) -> int:
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 99


def _sort_indicators(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (_severity_order(f.get("severity", "info")), -abs(f.get("points", 0))))


def _group_indicators(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {s: [] for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in groups:
            groups[sev].append(f)
    return groups


def classify_score(score: int) -> tuple[str, str]:
    if score < settings.RISK_BAND_MODERATE:
        return "Low", "LEGITIMATE"
    if score < settings.RISK_BAND_HIGH:
        return "Moderate", "SUSPICIOUS"
    if score < settings.RISK_BAND_CRITICAL:
        return "High", "PHISHING"
    return "Critical", "PHISHING"


def _category_score(findings: list[dict], cats: set[str]) -> int | None:
    relevant = [f for f in findings if f.get("category") in cats]
    if not relevant:
        return None
    pos, neg = 0.0, 0.0
    for f in relevant:
        pts = f.get("points", 0.0)
        if pts > 0:
            pos += pts
        else:
            neg += abs(pts)
    return round(max(saturate(pos) - neg, 0.0))


def _build_category_scores(findings: list[dict], ctx: dict) -> list[dict]:
    def _status(key: str) -> str:
        section = ctx.get(key)
        if isinstance(section, dict):
            return section.get("status", "unavailable")
        return "unavailable"

    return [
        {"key": "url", "label": "URL Security", "risk": _category_score(findings, {"url"}), "status": _status("url")},
        {"key": "domain", "label": "Domain Analysis", "risk": _category_score(findings, {"domain", "tls", "reputation"}), "status": _status("domain")},
        {"key": "page", "label": "Page Structure", "risk": _category_score(findings, {"webpage", "brand"}), "status": _status("webpage")},
        {"key": "redirect", "label": "Redirect Analysis", "risk": _category_score(findings, {"redirect"}), "status": _status("redirect")},
        {"key": "threat", "label": "Threat Indicators", "risk": _category_score(findings, {"rule", "ml"}), "status": "ok"},
    ]


def _compute_confidence(
    components: dict[str, dict],
    ml_section: dict | None,
    rule_result: dict,
    score: int,
    webpage_available: bool,
) -> int:
    available_count = sum(1 for c in components.values() if c["available"])
    total_count = len(components)
    data_completeness = available_count / total_count if total_count else 0.5

    ml_agrees = True
    if ml_section and ml_section.get("status") == "ok":
        ml_verdict = ml_section.get("ml_verdict")
        if ml_verdict == "PHISHING" and score < settings.RISK_BAND_HIGH:
            ml_agrees = False
        elif ml_verdict == "LEGITIMATE" and score >= settings.RISK_BAND_HIGH:
            ml_agrees = False
    agreement = 1.0 if ml_agrees else 0.7

    boundaries = [settings.RISK_BAND_MODERATE, settings.RISK_BAND_HIGH, settings.RISK_BAND_CRITICAL]
    min_dist = min(abs(score - b) for b in boundaries)
    boundary_factor = min(min_dist / 15.0, 1.0)

    confidence = data_completeness * agreement * boundary_factor * 100.0
    if not webpage_available:
        confidence *= 0.75
    return min(round(confidence), 98)


def _generate_summary(band: str, classification: str, score: int, top_findings: list[dict]) -> str:
    if classification == "LEGITIMATE":
        return "No major phishing indicators were detected from the available public signals."
    if classification == "SUSPICIOUS":
        return "Some suspicious indicators were detected. Exercise caution before providing personal information."
    return "Multiple strong phishing indicators were detected. This site poses a significant risk."


def _generate_explanation(top_findings: list[dict], components: dict[str, dict]) -> str:
    strong = [f for f in top_findings if f.get("severity") == "strong"]
    medium = [f for f in top_findings if f.get("severity") == "medium"]
    positive = [f for f in top_findings if f.get("severity") == "positive"]

    parts: list[str] = []
    if strong:
        msgs = [f["message"] for f in strong[:3]]
        parts.append("Primarily influenced by: " + "; ".join(msgs) + ".")
    if medium:
        msgs = [f["message"] for f in medium[:2]]
        parts.append("Additional factors: " + "; ".join(msgs) + ".")
    if positive:
        msgs = [f["message"] for f in positive[:2]]
        parts.append("Mitigating factors: " + "; ".join(msgs) + ".")
    if not parts:
        avail = [k for k, v in components.items() if v["available"]]
        parts.append(f"Assessment based on {len(avail)} available signal component(s).")
    return " ".join(parts)


def _generate_recommendation(classification: str) -> str:
    if classification == "LEGITIMATE":
        return "This URL appears safe based on available signals. Standard internet safety practices still apply."
    if classification == "SUSPICIOUS":
        return (
            "Proceed with caution. Verify the website address carefully before entering any personal information. "
            "Consider accessing the service directly through a known, trusted URL."
        )
    return (
        "Avoid interacting with this website. Do not enter any personal information, credentials, or payment details. "
        "If you believe you may have already been affected, change your passwords and monitor your accounts."
    )


def compute_risk(ctx: dict, rule_result: dict) -> dict:
    all_findings = _all_findings(ctx, rule_result)

    ml_section = ctx.get("ml")
    ml_available = isinstance(ml_section, dict) and ml_section.get("status") == "ok"
    ml_score = 0.0
    if ml_available:
        prob = ml_section.get("probability_phishing")
        ml_score = (prob * 100.0) if prob is not None else 0.0

    rule_pos, rule_neg = _sum_points(all_findings, {"url", "redirect", "rule"})
    rules_score = _component_score(rule_pos, rule_neg)

    wp_pos, wp_neg = _sum_points(all_findings, {"webpage", "brand"})
    webpage_score = _component_score(wp_pos, wp_neg)
    wp_section = ctx.get("webpage")
    webpage_available = isinstance(wp_section, dict) and wp_section.get("status") in ("ok", "restricted")

    dom_pos, dom_neg = _sum_points(all_findings, {"domain", "tls", "reputation"})
    domain_score = _component_score(dom_pos, dom_neg)
    dom_section = ctx.get("domain")
    domain_available = isinstance(dom_section, dict) and dom_section.get("status") in ("ok", "partial")

    rule_findings_exist = bool(rule_result.get("findings"))

    components: dict[str, dict[str, Any]] = {
        "ml": {
            "score": round(ml_score, 1),
            "weight": settings.WEIGHT_ML,
            "available": ml_available,
            "detail": f"P(phishing)={ml_section.get('probability_phishing', 'N/A')}" if ml_available else "Model unavailable",
        },
        "rules": {
            "score": round(rules_score, 1),
            "weight": settings.WEIGHT_RULES,
            "available": True,
            "detail": f"{len(rule_result.get('fired_rules', []))} rule(s) fired",
        },
        "webpage": {
            "score": round(webpage_score, 1),
            "weight": settings.WEIGHT_WEBPAGE,
            "available": webpage_available,
            "detail": f"Webpage {'analyzed' if webpage_available else 'unavailable'}",
        },
        "domain": {
            "score": round(domain_score, 1),
            "weight": settings.WEIGHT_DOMAIN,
            "available": domain_available,
            "detail": f"Domain {'analyzed' if domain_available else 'unavailable'}",
        },
    }

    total_weight = 0.0
    weighted_sum = 0.0
    weights_effective: dict[str, float] = {}
    for name, comp in components.items():
        if comp["available"]:
            total_weight += comp["weight"]

    for name, comp in components.items():
        if comp["available"] and total_weight > 0:
            ew = comp["weight"] / total_weight
        else:
            ew = 0.0
        weights_effective[name] = round(ew, 4)
        weighted_sum += ew * comp["score"]

    floor = rule_result.get("floor")
    floor_reason = rule_result.get("floor_reason")

    rep = (ctx.get("domain") or {}).get("reputation") or {}
    if rep.get("listed"):
        gsb_floor = 85
        if floor is None or gsb_floor > floor:
            floor = gsb_floor
            floor_reason = "Domain is flagged by Google Safe Browsing."

    raw_score = weighted_sum
    if floor is not None:
        raw_score = max(raw_score, float(floor))
    final_score = max(0, min(100, round(raw_score)))

    band, classification = classify_score(final_score)

    sorted_findings = _sort_indicators(all_findings)
    grouped = _group_indicators(sorted_findings)

    confidence = _compute_confidence(components, ml_section, rule_result, final_score, webpage_available)

    summary = _generate_summary(band, classification, final_score, sorted_findings)
    explanation = _generate_explanation(sorted_findings, components)
    recommendation = _generate_recommendation(classification)

    category_scores = _build_category_scores(all_findings, ctx)

    return {
        "risk_score": final_score,
        "risk_band": band,
        "classification": classification,
        "confidence": confidence,
        "summary": summary,
        "explanation": explanation,
        "recommendation": recommendation,
        "components": components,
        "weights_effective": weights_effective,
        "floor_applied": floor if floor is not None and floor <= final_score else None,
        "floor_reason": floor_reason if floor is not None and floor <= final_score else None,
        "category_scores": category_scores,
        "indicators": sorted_findings,
        "indicator_groups": grouped,
        "band_thresholds": {
            "moderate": settings.RISK_BAND_MODERATE,
            "high": settings.RISK_BAND_HIGH,
            "critical": settings.RISK_BAND_CRITICAL,
        },
        "method": "Weighted combination of ML probability, cross-signal rules, webpage structure and domain reputation with saturation normalization.",
    }
