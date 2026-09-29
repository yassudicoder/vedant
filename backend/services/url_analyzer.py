"""URL lexical and structural analysis for PhishGuard."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlsplit

from backend.config import settings
from backend.services.common import make_finding, truncate, UNAVAILABLE
from backend.security.validation import NormalizedURL
from ml.feature_extractor import (
    extract_ml_features,
    BRAND_OFFICIAL_DOMAINS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_HOST_KEYWORDS,
    parse_host,
    brands_outside_official_domain,
    brand_tokens_in_host,
    is_shared_hosting_subdomain,
    is_ip_literal,
)

SOURCE = "url_analyzer"

KNOWN_SHORTENERS: dict[str, str] = {
    "bit.ly": "Bitly",
    "bitly.com": "Bitly",
    "j.mp": "Bitly",
    "tinyurl.com": "TinyURL",
    "t.co": "Twitter/X",
    "goo.gl": "Google",
    "is.gd": "is.gd",
    "v.gd": "v.gd",
    "ow.ly": "Hootsuite",
    "rebrand.ly": "Rebrandly",
    "rb.gy": "Rebrandly",
    "cutt.ly": "Cuttly",
    "shorturl.at": "ShortURL",
    "shorturl.asia": "ShortURL",
    "tiny.cc": "TinyCC",
    "lnkd.in": "LinkedIn",
    "buff.ly": "Buffer",
    "adf.ly": "AdFly",
    "bl.ink": "BL.INK",
    "surl.li": "SURL",
    "qr.ae": "Quora",
    "amzn.to": "Amazon",
    "youtu.be": "YouTube",
    "fb.me": "Facebook",
    "bit.do": "bit.do",
    "shorte.st": "Shorte.st",
    "clck.ru": "Yandex",
    "trib.al": "Tribal",
    "mcaf.ee": "McAfee",
    "u.to": "u.to",
    "dub.sh": "Dub",
    "t.ly": "T.LY",
    "short.io": "Short.io",
    "han.gl": "Hangl",
    "reduced.to": "Reduced",
}

VOWELS = frozenset("aeiou")

_HEX_SEQ_RE = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
_PERCENT_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _random_domain_score(hostname: str) -> float:
    if not hostname:
        return 0.0
    consonant_chars = 0
    run = 0
    for ch in hostname:
        if ch.isalpha() and ch.lower() not in VOWELS:
            run += 1
        else:
            if run >= 2:
                consonant_chars += run
            run = 0
    if run >= 2:
        consonant_chars += run

    digit_chars = 0
    run = 0
    for ch in hostname:
        if ch.isdigit():
            run += 1
        else:
            if run >= 2:
                digit_chars += run
            run = 0
    if run >= 2:
        digit_chars += run

    return min((consonant_chars + digit_chars) / len(hostname), 1.0)


def _ip_version(hostname: str) -> int | None:
    if not is_ip_literal(hostname):
        return None
    host = hostname.strip("[]")
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return None


def _hostname_unicode(hostname: str) -> str:
    try:
        labels = hostname.split(".")
        decoded = []
        for label in labels:
            if label.startswith("xn--"):
                decoded.append(label.encode("ascii").decode("idna"))
            else:
                decoded.append(label)
        return ".".join(decoded)
    except (UnicodeError, UnicodeDecodeError):
        return hostname


def _special_char_count(url: str) -> int:
    return sum(1 for ch in url if ch in "@!#$%^&*()=+[]{}|;:',<>?~`")


def _suspicious_keywords_in_host(hostname: str) -> list[str]:
    host_lower = hostname.lower()
    return [kw for kw in SUSPICIOUS_HOST_KEYWORDS if kw in host_lower]


def analyze_url(nurl: NormalizedURL) -> dict:
    parts = parse_host(nurl.hostname)
    hostname = nurl.hostname
    registered_domain = parts.registered_domain
    subdomain = parts.subdomain
    tld = parts.suffix
    domain_label = parts.domain

    url_length = len(nurl.normalized)
    hostname_length = len(hostname)
    domain_length = len(domain_label)

    path = nurl.path
    path_length = len(path)
    path_segments = [s for s in path.split("/") if s]
    path_depth = len(path_segments)

    num_dots = hostname.count(".")
    num_subdomains = len([s for s in subdomain.split(".") if s]) if subdomain else 0
    num_hyphens = hostname.count("-")
    num_digits = sum(ch.isdigit() for ch in hostname)
    num_special_chars = _special_char_count(nurl.normalized)

    query = nurl.query
    num_query_params = len(parse_qs(query)) if query else 0
    num_path_params = sum(seg.count(";") for seg in path_segments)

    has_at_symbol = "@" in nurl.original
    has_ip = nurl.is_ip
    ip_version = _ip_version(hostname)

    has_punycode = any(
        label.startswith("xn--") for label in hostname.split(".") if label
    )

    percent_encoded_count = len(_PERCENT_ENC_RE.findall(nurl.normalized))
    has_suspicious_encoding = percent_encoded_count > 5 or "%25" in nurl.normalized.lower()

    has_double_slash_redirect = "//" in path[1:] if len(path) > 1 else False
    has_fragment = bool(nurl.fragment)

    has_non_standard_port = nurl.port is not None and nurl.port not in (80, 443)

    suspicious_tld = bool(
        tld
        and (tld in SUSPICIOUS_TLDS or tld.split(".")[-1] in SUSPICIOUS_TLDS)
    )
    suspicious_keywords = _suspicious_keywords_in_host(parts.hostname_no_www)
    suspicious_keyword_count = len(suspicious_keywords)

    is_shortener = (
        registered_domain in KNOWN_SHORTENERS or hostname in KNOWN_SHORTENERS
    )
    shortener_service = KNOWN_SHORTENERS.get(registered_domain) or KNOWN_SHORTENERS.get(hostname)

    random_score = _random_domain_score(parts.hostname_no_www)

    hex_alpha_count = sum(
        1 for ch in hostname if ch.lower() in "abcdef" and ch.isalpha()
    )
    hex_char_ratio = hex_alpha_count / len(hostname) if hostname else 0.0
    has_long_hex_sequence = bool(_HEX_SEQ_RE.search(hostname))

    domain_entropy = round(_shannon_entropy(domain_label), 6)

    brand_tokens = brand_tokens_in_host(parts)
    brands_outside = brands_outside_official_domain(parts)
    shared_hosting = is_shared_hosting_subdomain(parts) if not parts.is_ip else False

    ml_features = extract_ml_features(nurl.normalized)
    hostname_unicode = _hostname_unicode(hostname)

    # --- Findings ---
    findings: list[dict] = []

    if has_ip:
        findings.append(make_finding(
            "url.ip_host", "strong", "url",
            "URL uses a raw IP address instead of a domain name.",
            detail=f"Host: {hostname}",
            points=22, source=SOURCE,
        ))

    if has_at_symbol:
        findings.append(make_finding(
            "url.at_symbol", "medium", "url",
            "URL contains an '@' symbol, which can be used to obscure the real destination.",
            points=15, source=SOURCE,
        ))

    if nurl.scheme != "https" and not nurl.scheme_assumed:
        findings.append(make_finding(
            "url.no_https", "low", "url",
            "URL does not use HTTPS.",
            points=5, source=SOURCE,
        ))

    if has_non_standard_port:
        findings.append(make_finding(
            "url.non_standard_port", "medium", "url",
            f"URL uses a non-standard port ({nurl.port}).",
            detail=f"Port: {nurl.port}",
            points=12, source=SOURCE,
        ))

    if suspicious_tld:
        findings.append(make_finding(
            "url.suspicious_tld", "low", "url",
            f"Domain uses a TLD (.{tld}) frequently associated with abuse.",
            detail=f"TLD: .{tld}",
            points=6, source=SOURCE,
        ))

    if suspicious_keyword_count > 0:
        findings.append(make_finding(
            "url.suspicious_keywords", "low", "url",
            f"Hostname contains suspicious keywords: {', '.join(suspicious_keywords[:5])}.",
            detail=f"Keywords found: {', '.join(suspicious_keywords)}",
            points=min(5 + suspicious_keyword_count * 2, 8), source=SOURCE,
        ))

    if is_shortener:
        findings.append(make_finding(
            "url.shortener", "low", "url",
            f"URL uses a link shortening service ({shortener_service or registered_domain}).",
            detail=f"Service: {shortener_service or registered_domain}",
            points=5, source=SOURCE,
        ))

    if url_length > 100:
        findings.append(make_finding(
            "url.excessive_length", "low", "url",
            f"URL is unusually long ({url_length} characters).",
            points=4, source=SOURCE,
        ))

    if has_punycode:
        findings.append(make_finding(
            "url.punycode", "medium", "url",
            "Hostname contains internationalized (punycode) labels.",
            detail=f"Hostname: {hostname} (displays as {hostname_unicode})",
            points=10, source=SOURCE,
        ))

    if has_double_slash_redirect:
        findings.append(make_finding(
            "url.double_slash_redirect", "low", "url",
            "URL path contains a double-slash pattern that may indicate an open redirect.",
            points=4, source=SOURCE,
        ))

    if has_suspicious_encoding:
        findings.append(make_finding(
            "url.suspicious_encoding", "low", "url",
            "URL contains an unusual amount of percent-encoding.",
            detail=f"Encoded sequences found: {percent_encoded_count}",
            points=5, source=SOURCE,
        ))

    if random_score > 0.4:
        findings.append(make_finding(
            "url.random_domain", "medium", "url",
            "Domain name appears randomly generated.",
            detail=f"Random domain score: {random_score:.2f}",
            points=12, source=SOURCE,
        ))

    if has_long_hex_sequence:
        findings.append(make_finding(
            "url.long_hex_sequence", "low", "url",
            "Hostname contains a long hexadecimal sequence.",
            points=5, source=SOURCE,
        ))

    if brands_outside:
        findings.append(make_finding(
            "url.brand_impersonation", "medium", "url",
            f"Brand name(s) found in hostname on a non-official domain: {', '.join(brands_outside[:3])}.",
            detail=f"Brands: {', '.join(brands_outside)}, Domain: {registered_domain}",
            points=15, source=SOURCE,
        ))

    if shared_hosting:
        findings.append(make_finding(
            "url.shared_hosting", "low", "url",
            f"URL is hosted on a shared platform ({registered_domain}).",
            detail=f"Platform domain: {registered_domain}",
            points=4, source=SOURCE,
        ))

    if num_subdomains >= 3:
        findings.append(make_finding(
            "url.excessive_subdomains", "low", "url",
            f"Hostname has many subdomains ({num_subdomains}).",
            detail=f"Subdomain: {subdomain}",
            points=5, source=SOURCE,
        ))

    if domain_entropy > 4.0 and not parts.is_ip:
        findings.append(make_finding(
            "url.high_entropy", "low", "url",
            "Domain label has high character entropy, suggesting a randomly generated name.",
            detail=f"Entropy: {domain_entropy:.2f}",
            points=4, source=SOURCE,
        ))

    return {
        "status": "ok",
        "scheme": nurl.scheme,
        "https": nurl.scheme == "https",
        "scheme_assumed": nurl.scheme_assumed,
        "hostname": hostname,
        "hostname_unicode": hostname_unicode,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "tld": tld,
        "port": nurl.port,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "domain_length": domain_length,
        "path": truncate(path, 500),
        "path_length": path_length,
        "path_depth": path_depth,
        "num_dots": num_dots,
        "num_subdomains": num_subdomains,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "num_query_params": num_query_params,
        "num_path_params": num_path_params,
        "has_at_symbol": has_at_symbol,
        "has_ip": has_ip,
        "ip_version": ip_version,
        "has_punycode": has_punycode,
        "has_suspicious_encoding": has_suspicious_encoding,
        "percent_encoded_count": percent_encoded_count,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_fragment": has_fragment,
        "has_non_standard_port": has_non_standard_port,
        "suspicious_tld": suspicious_tld,
        "suspicious_keywords": suspicious_keywords,
        "suspicious_keyword_count": suspicious_keyword_count,
        "is_shortener": is_shortener,
        "shortener_service": shortener_service,
        "random_domain_score": round(random_score, 4),
        "hex_char_ratio": round(hex_char_ratio, 4),
        "has_long_hex_sequence": has_long_hex_sequence,
        "domain_entropy": domain_entropy,
        "brand_tokens": brand_tokens,
        "brands_outside_official": brands_outside,
        "shared_hosting": shared_hosting,
        "ml_features": ml_features,
        "findings": findings,
    }
