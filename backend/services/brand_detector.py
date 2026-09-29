"""
Brand impersonation detector for PhishGuard.

Detects brand references in multiple signals (hostname, page title, visible
text, favicon, form actions, copyright) and determines whether the hosting
domain is the brand's official property. Includes typosquatting detection
via edit distance, homoglyph substitution, combosquatting, and punycode
analysis.

Brand in title/text alone on a non-official domain is at most ``low``
severity; escalation to stronger findings requires additional signals such
as credential/payment forms (handled by the rule engine).
"""
from __future__ import annotations

import logging
import re
import unicodedata
from urllib.parse import urlsplit

from backend.services.common import make_finding, truncate
from ml.feature_extractor import (
    BRAND_OFFICIAL_DOMAINS,
    hostname_from_url,
    parse_host,
)

logger = logging.getLogger(__name__)

_SOURCE = "brand_detector"

# ------------------------------------------------------------------ #
# Homoglyph map: characters visually similar to ASCII letters.
# ------------------------------------------------------------------ #
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j",
    "һ": "h", "ԁ": "d",
    "ɑ": "a", "ɡ": "g", "ɯ": "m", "ɰ": "m",
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "ı": "i", "ł": "l",
}

# Brand display names (capitalised for human-readable output).
_BRAND_DISPLAY_NAMES: dict[str, str] = {
    "paypal": "PayPal", "apple": "Apple", "icloud": "iCloud",
    "microsoft": "Microsoft", "office365": "Office 365", "outlook": "Outlook",
    "onedrive": "OneDrive", "google": "Google", "gmail": "Gmail",
    "amazon": "Amazon", "facebook": "Facebook", "instagram": "Instagram",
    "whatsapp": "WhatsApp", "netflix": "Netflix", "linkedin": "LinkedIn",
    "twitter": "Twitter/X", "dropbox": "Dropbox", "adobe": "Adobe",
    "docusign": "DocuSign", "dhl": "DHL", "fedex": "FedEx",
    "usps": "USPS", "ebay": "eBay", "chase": "Chase",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America",
    "citibank": "Citibank", "hsbc": "HSBC", "sbi": "SBI",
    "onlinesbi": "OnlineSBI", "hdfc": "HDFC Bank", "icici": "ICICI Bank",
    "axisbank": "Axis Bank", "kotak": "Kotak", "paytm": "Paytm",
    "phonepe": "PhonePe", "flipkart": "Flipkart", "steam": "Steam",
    "coinbase": "Coinbase", "binance": "Binance", "metamask": "MetaMask",
    "yahoo": "Yahoo", "github": "GitHub", "spotify": "Spotify",
    "walmart": "Walmart", "irs": "IRS", "incometax": "Income Tax India",
}


# ------------------------------------------------------------------ #
# Levenshtein distance (pure-Python, bounded for performance).
# ------------------------------------------------------------------ #
def _levenshtein(s: str, t: str, max_dist: int = 5) -> int:
    """Compute bounded Levenshtein distance. Returns max_dist+1 if exceeded."""
    n, m = len(s), len(t)
    if abs(n - m) > max_dist:
        return max_dist + 1
    if n > m:
        s, t = t, s
        n, m = m, n
    prev = list(range(n + 1))
    for j in range(1, m + 1):
        curr = [j] + [0] * n
        for i in range(1, n + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[i] = min(curr[i - 1] + 1, prev[i] + 1, prev[i - 1] + cost)
        prev = curr
        if min(prev) > max_dist:
            return max_dist + 1
    return prev[n]


def _normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with their ASCII look-alike."""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    result = []
    for ch in nfkd:
        if ch in _HOMOGLYPHS:
            result.append(_HOMOGLYPHS[ch])
        elif ch.isascii():
            result.append(ch)
        # Skip combining marks or other non-ASCII after NFKD decomposition
    return "".join(result)


def _decode_punycode_domain(domain: str) -> str:
    """Decode an xn-- punycode domain label to unicode for analysis."""
    try:
        labels = []
        for label in domain.split("."):
            if label.startswith("xn--"):
                labels.append(label.encode("ascii").decode("idna"))
            else:
                labels.append(label)
        return ".".join(labels)
    except (UnicodeError, UnicodeDecodeError):
        return domain


def _check_typosquatting(
    hostname: str,
    registered_domain: str,
) -> dict:
    """
    Check if the domain is a typosquat of a known brand.

    Returns the typosquat sub-dict for the contract.
    """
    empty_result = {
        "detected": False, "brand": None, "official_domain": None,
        "similarity": 0.0, "technique": None,
    }

    if not registered_domain:
        return empty_result

    # Get the second-level label from registered_domain (e.g. "paypal" from "paypal.com")
    parts = parse_host(registered_domain)
    sld = parts.domain  # second-level domain label
    if not sld:
        return empty_result

    hostname_lower = hostname.lower()
    has_punycode = any(label.startswith("xn--") for label in hostname_lower.split("."))

    best_match: dict | None = None
    best_similarity = 0.0

    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if len(brand) < 3:
            continue

        # Skip if this IS the official domain
        if registered_domain in official_domains:
            continue

        # 1. Edit distance on the SLD
        dist = _levenshtein(sld, brand)
        # Only consider close matches (distance <= 2 for short brands, <= 3 for longer)
        max_allowed = 2 if len(brand) <= 6 else 3
        if 0 < dist <= max_allowed:
            similarity = 1.0 - (dist / max(len(sld), len(brand)))
            if similarity > best_similarity and similarity >= 0.6:
                best_match = {
                    "detected": True,
                    "brand": brand,
                    "official_domain": official_domains[0],
                    "similarity": round(similarity, 3),
                    "technique": "edit_distance",
                }
                best_similarity = similarity

        # 2. Homoglyph detection
        normalized_sld = _normalize_homoglyphs(sld)
        if normalized_sld != sld and normalized_sld == brand:
            best_match = {
                "detected": True,
                "brand": brand,
                "official_domain": official_domains[0],
                "similarity": 0.95,
                "technique": "homoglyph",
            }
            best_similarity = 0.95
            break  # Homoglyph is high confidence - stop

        # 3. Punycode tricks: decode and compare
        if has_punycode:
            decoded_host = _decode_punycode_domain(hostname_lower)
            decoded_parts = parse_host(decoded_host)
            decoded_sld = decoded_parts.domain
            if decoded_sld and decoded_sld != sld:
                # The decoded form might be the brand or a homoglyph of it
                normalized_decoded = _normalize_homoglyphs(decoded_sld)
                if normalized_decoded == brand or _levenshtein(decoded_sld, brand) <= 1:
                    similarity = 0.9
                    if similarity > best_similarity:
                        best_match = {
                            "detected": True,
                            "brand": brand,
                            "official_domain": official_domains[0],
                            "similarity": round(similarity, 3),
                            "technique": "punycode",
                        }
                        best_similarity = similarity

        # 4. Combosquatting: brand name + extra word joined
        #    e.g. "paypal-login.com", "paypalverify.com"
        sld_clean = sld.replace("-", "")
        if brand in sld_clean and sld_clean != brand and len(sld_clean) > len(brand):
            extra = sld_clean.replace(brand, "", 1)
            # Must have meaningful extra text, not just a single letter
            if len(extra) >= 2:
                similarity = round(len(brand) / len(sld_clean), 3)
                if similarity > best_similarity and similarity >= 0.4:
                    best_match = {
                        "detected": True,
                        "brand": brand,
                        "official_domain": official_domains[0],
                        "similarity": round(similarity, 3),
                        "technique": "combosquat",
                    }
                    best_similarity = similarity

    return best_match if best_match else empty_result


def analyze_brand(
    url_analysis: dict,
    webpage_analysis: dict | None,
    final_registered_domain: str | None,
) -> dict:
    """
    Detect brand references and potential impersonation.

    Parameters
    ----------
    url_analysis : dict
        Output of ``analyze_url``.
    webpage_analysis : dict or None
        Output of ``analyze_webpage`` (may be ``None`` or have non-ok status).
    final_registered_domain : str or None
        The registered domain of the final (post-redirect) URL.

    Returns
    -------
    dict
        Brand analysis conforming to contract section 3.5.
    """
    findings: list[dict] = []
    brands_detected: list[dict] = []
    impersonation_suspected = False

    hostname = url_analysis.get("hostname", "")
    registered_domain = final_registered_domain or url_analysis.get("registered_domain", "")

    # Gather brand signals from multiple sources.
    brand_signals: dict[str, set[str]] = {}  # brand -> set of sources

    # 1. Hostname-based detection (from url_analysis)
    brand_tokens = url_analysis.get("brand_tokens", [])
    for brand in brand_tokens:
        brand_signals.setdefault(brand, set()).add("hostname")

    # Also check brands_outside_official from url_analysis
    brands_outside = url_analysis.get("brands_outside_official", [])

    # 2. Webpage-based detection
    wp_ok = (
        webpage_analysis is not None
        and webpage_analysis.get("status") == "ok"
    )

    if wp_ok:
        # Title
        title = (webpage_analysis.get("title") or "").lower()
        title_clean = title.replace("-", "").replace(".", "")
        for brand in BRAND_OFFICIAL_DOMAINS:
            if len(brand) >= 3 and brand in title_clean:
                brand_signals.setdefault(brand, set()).add("title")

        # Visible text (brand_text_mentions from webpage_analyzer)
        brand_text_mentions = webpage_analysis.get("brand_text_mentions", [])
        for brand in brand_text_mentions:
            brand_signals.setdefault(brand, set()).add("text")

        # Favicon
        favicon = webpage_analysis.get("favicon", {})
        if favicon.get("external") and favicon.get("domain"):
            fav_domain = favicon["domain"].lower()
            for brand, official in BRAND_OFFICIAL_DOMAINS.items():
                if fav_domain in official:
                    brand_signals.setdefault(brand, set()).add("favicon")

        # Form action domains
        forms = webpage_analysis.get("forms", {})
        action_domains = forms.get("action_domains", [])
        for act_domain in action_domains:
            act_lower = act_domain.lower()
            for brand, official in BRAND_OFFICIAL_DOMAINS.items():
                if act_lower in official:
                    brand_signals.setdefault(brand, set()).add("form_action")

        # Copyright text
        copyright_text = (webpage_analysis.get("copyright_text") or "").lower()
        if copyright_text:
            copyright_clean = copyright_text.replace("-", "").replace(".", "")
            for brand in BRAND_OFFICIAL_DOMAINS:
                if len(brand) >= 3 and brand in copyright_clean:
                    brand_signals.setdefault(brand, set()).add("copyright")

    # Build brands_detected list.
    for brand, sources in brand_signals.items():
        official = BRAND_OFFICIAL_DOMAINS.get(brand, ())
        domain_matches = registered_domain in official if registered_domain else False
        brands_detected.append({
            "brand": brand,
            "display_name": _BRAND_DISPLAY_NAMES.get(brand, brand.title()),
            "sources": sorted(sources),
            "official_domains": list(official[:5]),
            "domain_matches_official": domain_matches,
        })

    # Determine impersonation.
    non_official_brands = [
        b for b in brands_detected if not b["domain_matches_official"]
    ]

    if non_official_brands:
        impersonation_suspected = True

    # Typosquatting check.
    typosquat = _check_typosquatting(hostname, registered_domain)

    # Build explanation.
    explanation: str | None = None
    if not brands_detected:
        explanation = "No known brand references detected."
    elif not impersonation_suspected:
        brand_names = ", ".join(b["display_name"] for b in brands_detected[:3])
        explanation = f"Brand references found ({brand_names}) on an official domain."
    else:
        brand_names = ", ".join(b["display_name"] for b in non_official_brands[:3])
        explanation = truncate(
            f"Brand references to {brand_names} detected on a domain that is not "
            f"an official property of the brand. This may indicate impersonation.",
            300,
        )

    # --- Findings ---------------------------------------------------------- #

    # Brand detected in hostname on non-official domain.
    for b in non_official_brands:
        if "hostname" in b["sources"]:
            findings.append(make_finding(
                "brand.name_in_hostname", "medium", "brand",
                f"Brand name '{b['display_name']}' appears in the hostname but the domain "
                f"is not an official {b['display_name']} property.",
                detail=truncate(f"Domain: {registered_domain}, Official: {', '.join(b['official_domains'][:3])}", 300),
                points=15, source=_SOURCE,
            ))

    # Brand in title/text ONLY on non-official domain -> at most low severity.
    for b in non_official_brands:
        text_only_sources = b["sources"] - {"hostname"}
        has_only_text = text_only_sources and text_only_sources <= {"title", "text", "copyright"}
        has_hostname = "hostname" in b["sources"]
        if has_only_text and not has_hostname:
            findings.append(make_finding(
                "brand.name_in_content", "low", "brand",
                f"Brand name '{b['display_name']}' found in page content but not in hostname.",
                detail=truncate(f"Sources: {', '.join(sorted(text_only_sources))}", 200),
                points=5, source=_SOURCE,
            ))

    # Brand in favicon on non-official domain.
    for b in non_official_brands:
        if "favicon" in b["sources"]:
            findings.append(make_finding(
                "brand.favicon_mismatch", "low", "brand",
                f"Favicon references {b['display_name']} but domain is not official.",
                points=6, source=_SOURCE,
            ))

    # Brand form action pointing to official while domain is not.
    for b in non_official_brands:
        if "form_action" in b["sources"]:
            findings.append(make_finding(
                "brand.form_action_official", "low", "brand",
                f"Form submits to {b['display_name']}'s official domain from a non-official page.",
                points=4, source=_SOURCE,
            ))

    # Typosquatting findings.
    if typosquat["detected"]:
        brand_display = _BRAND_DISPLAY_NAMES.get(typosquat["brand"], typosquat["brand"])
        technique = typosquat["technique"]
        severity = "medium"
        points = 16.0
        if technique == "homoglyph" or technique == "punycode":
            severity = "strong"
            points = 25.0

        findings.append(make_finding(
            f"brand.typosquat_{technique}", severity, "brand",
            f"Domain appears to be a typosquat of {brand_display} "
            f"({technique} technique, similarity {typosquat['similarity']:.0%}).",
            detail=truncate(f"Official: {typosquat['official_domain']}, Registered: {registered_domain}", 300),
            points=points, source=_SOURCE,
        ))

    # Positive: domain matches official brand.
    official_brands = [b for b in brands_detected if b["domain_matches_official"]]
    if official_brands and not impersonation_suspected:
        brand_names = ", ".join(b["display_name"] for b in official_brands[:3])
        findings.append(make_finding(
            "brand.official_domain", "positive", "brand",
            f"Domain belongs to the official {brand_names} property.",
            points=-8, source=_SOURCE,
        ))

    return {
        "status": "ok",
        "brands_detected": brands_detected,
        "impersonation_suspected": impersonation_suspected,
        "typosquat": typosquat,
        "explanation": explanation,
        "findings": findings,
    }
