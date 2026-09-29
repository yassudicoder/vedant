"""
Rule engine: cross-signal combination rules for PhishGuard.

Rules are declared as data so they can be listed on the methodology page and
evaluated programmatically. A single rule NEVER sets a risk floor; only
multi-signal combinations may establish a floor.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.services.common import make_finding

log = logging.getLogger(__name__)


def _safe(ctx: dict, *keys: str, default: Any = None) -> Any:
    obj = ctx
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k, default)
        if obj is default:
            return default
    return obj


def _ok(ctx: dict, key: str) -> bool:
    section = ctx.get(key)
    return isinstance(section, dict) and section.get("status") == "ok"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str
    points: float
    predicate: Callable[[dict], list[str] | None]
    floor: int | None = None
    floor_reason: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "points": self.points,
        }
        if self.floor is not None:
            d["floor"] = self.floor
            d["floor_reason"] = self.floor_reason
        return d


def _rule_ip_host_suspicious_keywords(ctx: dict) -> list[str] | None:
    if not _ok(ctx, "url"):
        return None
    url = ctx["url"]
    if url.get("has_ip") and url.get("suspicious_keyword_count", 0) > 0:
        kws = ", ".join(url.get("suspicious_keywords", [])[:5])
        return [f"IP literal host with suspicious keywords: {kws}"]
    return None


def _rule_long_url_redirects_structure(ctx: dict) -> list[str] | None:
    evidence = []
    url = ctx.get("url") or {}
    redir = ctx.get("redirect") or {}
    if url.get("url_length", 0) >= 75:
        evidence.append(f"URL length {url['url_length']}")
    if redir.get("num_redirects", 0) >= 2:
        evidence.append(f"{redir['num_redirects']} redirects")
    suspicious_struct = (
        url.get("has_at_symbol")
        or url.get("has_double_slash_redirect")
        or url.get("suspicious_keyword_count", 0) >= 2
        or url.get("num_subdomains", 0) >= 3
    )
    if suspicious_struct:
        evidence.append("suspicious URL structure")
    if len(evidence) >= 2:
        return evidence
    return None


def _rule_brand_impersonation_domain_mismatch(ctx: dict) -> list[str] | None:
    if not _ok(ctx, "brand"):
        return None
    brand = ctx["brand"]
    if not brand.get("impersonation_suspected"):
        return None
    brands = brand.get("brands_detected") or []
    mismatched = [b["brand"] for b in brands if not b.get("domain_matches_official")]
    if mismatched:
        return [f"Brand impersonation detected ({', '.join(mismatched[:3])}) on non-official domain"]
    return None


def _rule_credential_form_brand_mismatch(ctx: dict) -> list[str] | None:
    wp = ctx.get("webpage") or {}
    brand = ctx.get("brand") or {}
    forms = wp.get("forms") or {}
    has_cred = forms.get("with_password", 0) > 0 or forms.get("login_form")
    if not has_cred:
        return None
    if not brand.get("impersonation_suspected"):
        return None
    brands = brand.get("brands_detected") or []
    mismatched = [b["brand"] for b in brands if not b.get("domain_matches_official")]
    if mismatched:
        return [
            "Credential/login form present",
            f"Brand mismatch: {', '.join(mismatched[:3])}",
        ]
    return None


def _rule_password_form_external_insecure(ctx: dict) -> list[str] | None:
    wp = ctx.get("webpage") or {}
    forms = wp.get("forms") or {}
    if not forms.get("with_password", 0):
        return None
    evidence = []
    if forms.get("external_action_count", 0) > 0:
        domains = forms.get("action_domains", [])[:3]
        evidence.append(f"Password form posts to external domain(s): {', '.join(domains) if domains else 'external'}")
    if forms.get("insecure_action"):
        evidence.append("Password form posts to insecure (HTTP) endpoint")
    if evidence:
        return evidence
    return None


def _rule_young_domain_login(ctx: dict) -> list[str] | None:
    dom = ctx.get("domain") or {}
    wp = ctx.get("webpage") or {}
    reg = dom.get("registration") or {}
    age = reg.get("domain_age_days")
    if age is None or age >= 30:
        return None
    has_login = wp.get("has_login_wording") or wp.get("has_password_field")
    if has_login:
        return [f"Domain age {age} days (<30)", "Login/password content detected"]
    return None


def _rule_punycode_typosquat_brand(ctx: dict) -> list[str] | None:
    url = ctx.get("url") or {}
    brand = ctx.get("brand") or {}
    typo = brand.get("typosquat") or {}
    has_puny = url.get("has_punycode")
    has_typo = typo.get("detected")
    if not (has_puny or has_typo):
        return None
    brands = brand.get("brands_detected") or []
    brand_names = [b["brand"] for b in brands]
    if not brand_names and typo.get("brand"):
        brand_names = [typo["brand"]]
    if not brand_names:
        return None
    evidence = []
    if has_puny:
        evidence.append("Punycode (IDN) hostname")
    if has_typo:
        technique = typo.get("technique", "unknown")
        evidence.append(f"Typosquat detected ({technique})")
    evidence.append(f"Brands: {', '.join(brand_names[:3])}")
    return evidence


def _rule_shortener_cross_domain(ctx: dict) -> list[str] | None:
    url = ctx.get("url") or {}
    redir = ctx.get("redirect") or {}
    if not url.get("is_shortener"):
        return None
    if redir.get("crossed_domains"):
        return [
            f"URL shortener ({url.get('shortener_service', 'detected')})",
            "Cross-domain redirect detected",
        ]
    return None


def _rule_https_valid(ctx: dict) -> list[str] | None:
    tls = ctx.get("tls") or {}
    if tls.get("certificate_valid") and tls.get("https_available"):
        return ["Valid HTTPS certificate"]
    return None


def _rule_established_popular(ctx: dict) -> list[str] | None:
    dom = ctx.get("domain") or {}
    reg = dom.get("registration") or {}
    pop = dom.get("popularity") or {}
    age = reg.get("domain_age_days")
    if age is None or age < 365:
        return None
    if pop.get("available") and pop.get("rank") is not None:
        return [f"Domain age {age} days (>1yr)", f"Tranco rank {pop['rank']}"]
    return None


def _rule_invalid_cert_password(ctx: dict) -> list[str] | None:
    tls = ctx.get("tls") or {}
    wp = ctx.get("webpage") or {}
    if tls.get("certificate_valid") is not False:
        return None
    if wp.get("has_password_field"):
        return ["Invalid TLS certificate", "Password field present"]
    return None


def _rule_gsb_listed(ctx: dict) -> list[str] | None:
    dom = ctx.get("domain") or {}
    rep = dom.get("reputation") or {}
    if rep.get("listed"):
        threats = ", ".join(rep.get("threats", [])[:3]) or "malicious"
        return [f"Google Safe Browsing: {threats}"]
    return None


def _rule_multiple_suspicious_signals(ctx: dict) -> list[str] | None:
    """Catch-all: several independent medium-severity signals together."""
    signals = []
    url = ctx.get("url") or {}
    wp = ctx.get("webpage") or {}
    redir = ctx.get("redirect") or {}
    dom = ctx.get("domain") or {}
    tls = ctx.get("tls") or {}

    if url.get("suspicious_tld"):
        signals.append("suspicious TLD")
    if url.get("random_domain_score", 0) > 0.7:
        signals.append("random-looking domain")
    if wp.get("has_password_field") and not wp.get("has_login_wording"):
        signals.append("hidden password intent")
    if redir.get("https_downgrade"):
        signals.append("HTTPS downgrade in redirects")
    if tls.get("self_signed"):
        signals.append("self-signed certificate")
    reg = dom.get("registration") or {}
    age = reg.get("domain_age_days")
    if age is not None and age < 7:
        signals.append(f"very young domain ({age}d)")
    forms = wp.get("forms") or {}
    if forms.get("hidden_input_count", 0) >= 5:
        signals.append("many hidden inputs")
    if len(signals) >= 3:
        return signals
    return None


def _rule_https_downgrade_credential(ctx: dict) -> list[str] | None:
    redir = ctx.get("redirect") or {}
    wp = ctx.get("webpage") or {}
    if not redir.get("https_downgrade"):
        return None
    forms = wp.get("forms") or {}
    if forms.get("with_password", 0) > 0 or forms.get("login_form"):
        return ["HTTPS downgrade in redirect chain", "Login/password form present"]
    return None


def _rule_hidden_iframes_login(ctx: dict) -> list[str] | None:
    wp = ctx.get("webpage") or {}
    iframes = wp.get("iframes") or {}
    if iframes.get("hidden", 0) < 1:
        return None
    if wp.get("has_password_field") or wp.get("has_login_wording"):
        return [f"{iframes['hidden']} hidden iframe(s)", "Login content detected"]
    return None


RULES: list[Rule] = [
    Rule(
        id="rule.ip_host_keywords",
        name="IP host with suspicious keywords",
        description="The URL uses a raw IP address combined with phishing-related keywords in the path or hostname.",
        severity="medium",
        points=15.0,
        predicate=_rule_ip_host_suspicious_keywords,
    ),
    Rule(
        id="rule.long_url_redirects_structure",
        name="Long URL with redirects and suspicious structure",
        description="An unusually long URL combined with multiple redirects and/or suspicious structural elements.",
        severity="medium",
        points=14.0,
        predicate=_rule_long_url_redirects_structure,
    ),
    Rule(
        id="rule.brand_impersonation_domain_mismatch",
        name="Brand impersonation on non-official domain",
        description="A well-known brand is referenced on a domain that does not belong to that brand.",
        severity="strong",
        points=25.0,
        predicate=_rule_brand_impersonation_domain_mismatch,
    ),
    Rule(
        id="rule.credential_form_brand_mismatch",
        name="Credential form with brand mismatch",
        description="A login or password form is present on a page impersonating a brand on a non-official domain.",
        severity="strong",
        points=30.0,
        predicate=_rule_credential_form_brand_mismatch,
        floor=70,
        floor_reason="Credential form on a page impersonating a brand on a non-official domain.",
    ),
    Rule(
        id="rule.password_external_insecure",
        name="Password form to external or insecure domain",
        description="A password field submits data to an external domain or over an insecure HTTP connection.",
        severity="strong",
        points=25.0,
        predicate=_rule_password_form_external_insecure,
    ),
    Rule(
        id="rule.young_domain_login",
        name="Young domain with login content",
        description="The domain was registered less than 30 days ago and the page contains login or password content.",
        severity="strong",
        points=22.0,
        predicate=_rule_young_domain_login,
        floor=60,
        floor_reason="Recently registered domain with credential-harvesting indicators.",
    ),
    Rule(
        id="rule.punycode_typosquat_brand",
        name="Punycode or typosquat targeting a brand",
        description="The hostname uses IDN/punycode encoding or typosquatting techniques to mimic a known brand.",
        severity="strong",
        points=28.0,
        predicate=_rule_punycode_typosquat_brand,
        floor=65,
        floor_reason="Punycode/typosquat domain impersonating a known brand.",
    ),
    Rule(
        id="rule.shortener_cross_domain",
        name="URL shortener with cross-domain redirect",
        description="A URL shortener redirects to a different domain, potentially hiding the true destination.",
        severity="medium",
        points=12.0,
        predicate=_rule_shortener_cross_domain,
    ),
    Rule(
        id="rule.https_valid_reduction",
        name="Valid HTTPS certificate",
        description="The site presents a valid, trusted HTTPS certificate (small risk reduction only).",
        severity="positive",
        points=-5.0,
        predicate=_rule_https_valid,
    ),
    Rule(
        id="rule.established_popular",
        name="Established and popular domain",
        description="The domain is over one year old and appears in the Tranco popularity list.",
        severity="positive",
        points=-12.0,
        predicate=_rule_established_popular,
    ),
    Rule(
        id="rule.invalid_cert_password",
        name="Invalid certificate with password field",
        description="The site has an invalid TLS certificate and contains a password entry field.",
        severity="strong",
        points=28.0,
        predicate=_rule_invalid_cert_password,
        floor=65,
        floor_reason="Invalid certificate combined with password field.",
    ),
    Rule(
        id="rule.gsb_listed",
        name="Google Safe Browsing threat",
        description="The domain is flagged by Google Safe Browsing as hosting malicious content.",
        severity="strong",
        points=35.0,
        predicate=_rule_gsb_listed,
    ),
    Rule(
        id="rule.multiple_suspicious_signals",
        name="Multiple suspicious signals",
        description="Three or more independent medium-severity indicators are present simultaneously.",
        severity="medium",
        points=16.0,
        predicate=_rule_multiple_suspicious_signals,
    ),
    Rule(
        id="rule.https_downgrade_credential",
        name="HTTPS downgrade with credential form",
        description="The redirect chain downgrades from HTTPS to HTTP and the page contains login forms.",
        severity="strong",
        points=24.0,
        predicate=_rule_https_downgrade_credential,
        floor=60,
        floor_reason="HTTPS downgrade combined with credential form.",
    ),
    Rule(
        id="rule.hidden_iframes_login",
        name="Hidden iframes with login content",
        description="Hidden iframes are present alongside login or password content.",
        severity="medium",
        points=15.0,
        predicate=_rule_hidden_iframes_login,
    ),
]


def evaluate_rules(ctx: dict) -> dict:
    fired: list[dict] = []
    findings: list[dict] = []
    floor: int | None = None
    floor_reason: str | None = None

    for rule in RULES:
        try:
            evidence = rule.predicate(ctx)
        except Exception:
            log.exception("Rule %s raised an exception", rule.id)
            continue
        if evidence is None:
            continue
        fired.append({
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "points": rule.points,
            "evidence": evidence,
        })
        findings.append(make_finding(
            rule.id,
            rule.severity,
            "rule",
            rule.description,
            detail="; ".join(evidence),
            points=rule.points,
            source="rule_engine",
        ))
        if rule.floor is not None and (floor is None or rule.floor > floor):
            floor = rule.floor
            floor_reason = rule.floor_reason

    return {
        "status": "ok",
        "fired_rules": fired,
        "findings": findings,
        "floor": floor,
        "floor_reason": floor_reason,
    }


def list_rules() -> list[dict]:
    return [r.to_dict() for r in RULES]
