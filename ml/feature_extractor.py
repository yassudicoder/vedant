"""
Shared ML feature extraction for PhishGuard.

This module is imported by BOTH the offline training code (ml/train.py) and the
live backend (backend/services/ml_detector.py), which guarantees that the model
sees identically computed features at training and inference time
(no train/serve skew).

Design decision - host-level lexical features only
--------------------------------------------------
The training corpus (PhiUSIIL, UCI id 967) has strong collection artifacts:

* every legitimate URL is a bare homepage (no path, no query),
* every legitimate URL uses HTTPS and the ``www.`` prefix,
* page-content columns reflect pages that were mostly dead/empty at crawl
  time for the phishing class.

A model trained on path/query/scheme features would therefore learn *how the
dataset was collected* rather than *what phishing looks like*
(e.g. "has a path => phishing"). ml/evaluate.py quantifies this
("bias analysis"). To avoid it, the model uses only features of the
hostname, computed after removing a leading ``www.`` label. Path, query,
scheme, redirect and page signals are evaluated by the rule engine instead.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract

# Offline Public Suffix List snapshot bundled with tldextract - never performs
# network requests (important both for reproducibility and for SSRF hygiene).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# --------------------------------------------------------------------------- #
# Reference vocabularies (domain knowledge, not learned from the dataset)
# --------------------------------------------------------------------------- #
SUSPICIOUS_HOST_KEYWORDS: tuple[str, ...] = (
    "login", "log-in", "signin", "sign-in", "logon", "secure", "security", "account",
    "verify", "verification", "update", "confirm", "banking", "webscr", "cmd",
    "support", "service", "billing", "wallet", "auth", "recovery", "unlock",
    "suspend", "alert", "validate", "authenticate", "password", "credential",
    "invoice", "refund", "payment", "customer", "helpdesk", "reactivate",
)

# TLDs repeatedly over-represented in phishing/abuse reports (e.g. Interisle
# "Phishing Landscape", Spamhaus "Most abused TLDs"). A prior, not a verdict.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz", "cyou", "rest", "sbs",
    "click", "link", "work", "zip", "mov", "cam", "monster", "quest", "bond", "cfd",
    "lol", "shop", "online", "site", "live", "support", "loan", "win", "bid", "vip",
    "country", "kim", "men", "party", "review", "stream", "gdn", "racing", "date",
    "faith", "science", "cricket", "accountant", "download", "trade", "webcam", "ru.com",
})

# Brand tokens mapped to the registrable domains legitimately operated by the
# brand. Used for the "brand token outside the official domain" feature.
# The backend brand detector (backend/services/brand_detector.py) may use a
# richer list; this compact list is frozen for the ML model.
BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "apple": ("apple.com", "icloud.com", "apple.co"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "azure.com", "msn.com", "windows.com", "xbox.com", "office365.com", "sharepoint.com", "onedrive.com", "bing.com"),
    "office365": ("office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "microsoft.com", "office.com"),
    "onedrive": ("onedrive.com", "live.com", "microsoft.com"),
    "google": ("google.com", "google.co.in", "gmail.com", "youtube.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "withgoogle.com", "google.co.uk"),
    "gmail": ("gmail.com", "google.com"),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.co.jp", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "aws.amazon.com", "primevideo.com"),
    "facebook": ("facebook.com", "fb.com", "meta.com", "fbcdn.net", "facebook.net"),
    "instagram": ("instagram.com", "cdninstagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "netflix": ("netflix.com", "nflxext.com", "nflximg.net"),
    "linkedin": ("linkedin.com", "licdn.com"),
    "twitter": ("twitter.com", "x.com", "twimg.com", "t.co"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "adobe": ("adobe.com", "adobelogin.com", "typekit.net"),
    "docusign": ("docusign.com", "docusign.net"),
    "dhl": ("dhl.com", "dhl.de", "dhl.co.in"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "ebay": ("ebay.com", "ebay.in", "ebay.co.uk", "ebay.de", "ebayimg.com"),
    "chase": ("chase.com", "jpmorganchase.com"),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "citibank": ("citi.com", "citibank.com", "citibank.co.in"),
    "hsbc": ("hsbc.com", "hsbc.co.in", "hsbc.co.uk"),
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi"),
    "onlinesbi": ("onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcbank.net"),
    "icici": ("icicibank.com", "icicidirect.com", "icicilombard.com"),
    "axisbank": ("axisbank.com", "axisbank.co.in"),
    "kotak": ("kotak.com", "kotaksecurities.com"),
    "paytm": ("paytm.com", "paytm.in", "paytmbank.com"),
    "phonepe": ("phonepe.com",),
    "flipkart": ("flipkart.com",),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "yahoo": ("yahoo.com", "yahoo.co.in", "yimg.com"),
    "github": ("github.com", "github.io", "githubusercontent.com"),
    "spotify": ("spotify.com", "scdn.co"),
    "walmart": ("walmart.com",),
    "irs": ("irs.gov",),
    "incometax": ("incometax.gov.in",),
}

# Registrable domains that host content from many unrelated customers.
# A subdomain on these says nothing about the platform owner's trust.
SHARED_HOSTING_DOMAINS: frozenset[str] = frozenset({
    "000webhostapp.com", "weebly.com", "wixsite.com", "wix.com", "firebaseapp.com", "web.app",
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "herokuapp.com", "blogspot.com", "wordpress.com", "glitch.me", "repl.co", "replit.app",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "cloudfront.net",
    "appspot.com", "godaddysites.com", "square.site", "webflow.io", "carrd.co", "sites.google.com",
    "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "myftp.biz",
    "byethost.com", "epizy.com", "rf.gd", "infinityfreeapp.com", "freenom.com", "yolasite.com",
    "jimdosite.com", "strikingly.com", "mystrikingly.com", "tilda.ws", "notion.site", "canva.site",
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "fleek.co", "surge.sh", "render.com", "onrender.com",
    "fly.dev", "railway.app", "codesandbox.io", "csb.app", "framer.app", "framer.website",
    "typedream.app", "gitbook.io", "webcindario.com", "altervista.org", "s3.amazonaws.com",
    "storage.googleapis.com", "blob.core.windows.net", "r2.dev", "b-cdn.net", "backblazeb2.com",
})

VOWELS = set("aeiou")

# --------------------------------------------------------------------------- #
# Feature schema - ORDER MATTERS (it is the model's column order).
# --------------------------------------------------------------------------- #
ML_FEATURE_NAMES: tuple[str, ...] = (
    "host_length",               # len(hostname) after stripping a leading "www."
    "domain_length",             # len(second-level label), e.g. "paypal" -> 6
    "num_dots",                  # dots in hostname (sans www)
    "num_hyphens",               # hyphens in hostname
    "num_digits",                # digits in hostname
    "digit_ratio",               # digits / host_length
    "num_subdomains",            # labels before the registrable domain (sans www)
    "subdomain_length",          # total length of the subdomain part
    "longest_label_length",      # longest DNS label
    "has_ip",                    # hostname is an IPv4/IPv6 literal
    "punycode",                  # any label starts with "xn--"
    "tld_length",                # length of the public suffix
    "suspicious_tld",            # public suffix in SUSPICIOUS_TLDS
    "domain_entropy",            # Shannon entropy of the second-level label
    "vowel_ratio",               # vowels / letters in second-level label
    "max_consonant_run",         # longest consonant streak in hostname
    "max_digit_run",             # longest digit streak in hostname
    "max_repeat_run",            # longest run of the same character
    "suspicious_keyword_count",  # SUSPICIOUS_HOST_KEYWORDS occurrences in hostname
    "brand_outside_official",    # a brand token appears in host but domain is not official
    "shared_hosting_subdomain",  # customer subdomain on a shared hosting platform
)


@dataclass(frozen=True)
class HostParts:
    """Decomposition of a hostname using the Public Suffix List."""

    hostname: str            # lower-case, IDNA (punycode) form, no trailing dot
    hostname_no_www: str     # hostname with ONE leading "www." removed
    subdomain: str           # e.g. "secure.login" (sans leading www)
    domain: str              # second-level label, e.g. "paypal"
    suffix: str              # public suffix, e.g. "co.in"
    registered_domain: str   # e.g. "paypal.co.in" ("" for IPs / unknown suffix)
    is_ip: bool


def _to_idna(hostname: str) -> str:
    hostname = hostname.strip().strip(".").lower()
    if not hostname:
        return ""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        # Fall back label-by-label; keep what cannot be encoded as-is.
        labels = []
        for label in hostname.split("."):
            try:
                labels.append(label.encode("idna").decode("ascii") if label else label)
            except UnicodeError:
                labels.append(label)
        return ".".join(labels)


def is_ip_literal(hostname: str) -> bool:
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def parse_host(hostname: str) -> HostParts:
    """Split a hostname into PSL-aware parts. Never touches the network."""
    host = _to_idna(hostname)
    if is_ip_literal(host):
        return HostParts(host, host, "", "", "", "", True)
    no_www = host[4:] if host.startswith("www.") and host.count(".") >= 2 else host
    ext = _EXTRACT(no_www)
    subdomain = ext.subdomain or ""
    registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""
    return HostParts(
        hostname=host,
        hostname_no_www=no_www,
        subdomain=subdomain,
        domain=ext.domain or "",
        suffix=ext.suffix or "",
        registered_domain=registered,
        is_ip=False,
    )


def hostname_from_url(url: str) -> str:
    """Best-effort hostname extraction for URLs with or without a scheme."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        host = ""
    return host


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _max_run(text: str, predicate) -> int:
    best = current = 0
    for ch in text:
        if predicate(ch):
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def _max_repeat_run(text: str) -> int:
    best = current = 0
    previous = None
    for ch in text:
        current = current + 1 if ch == previous else 1
        previous = ch
        best = max(best, current)
    return best


def is_official_brand_domain(registered_domain: str, brand: str) -> bool:
    official = BRAND_OFFICIAL_DOMAINS.get(brand, ())
    return registered_domain in official


def brand_tokens_in_host(parts: HostParts) -> list[str]:
    """Brand tokens found anywhere in the hostname (sans www)."""
    host = parts.hostname_no_www.replace("-", "").replace(".", "")
    return [brand for brand in BRAND_OFFICIAL_DOMAINS if len(brand) >= 3 and brand in host]


def brands_outside_official_domain(parts: HostParts) -> list[str]:
    """Brand tokens present in the host while the registrable domain is not official."""
    found = []
    for brand in brand_tokens_in_host(parts):
        if not is_official_brand_domain(parts.registered_domain, brand):
            found.append(brand)
    return found


def is_shared_hosting_subdomain(parts: HostParts) -> bool:
    if not parts.subdomain:
        return False
    if parts.registered_domain in SHARED_HOSTING_DOMAINS:
        return True
    # Multi-label platform domains such as "sites.google.com" / "s3.amazonaws.com".
    host = parts.hostname_no_www
    return any(host.endswith("." + platform) for platform in SHARED_HOSTING_DOMAINS if platform.count(".") >= 2)


def extract_ml_features(url_or_host: str) -> dict[str, float]:
    """
    Compute the model's feature vector from a URL (or bare hostname).

    Returns a dict keyed by ML_FEATURE_NAMES. Numeric values only.
    """
    hostname = hostname_from_url(url_or_host) if ("/" in url_or_host or ":" in url_or_host) else url_or_host
    parts = parse_host(hostname or "")
    host = parts.hostname_no_www
    host_len = len(host)
    digits = sum(ch.isdigit() for ch in host)
    labels = [label for label in host.split(".") if label]
    sld = parts.domain if not parts.is_ip else ""
    letters = [ch for ch in sld if ch.isalpha()]

    keyword_count = 0
    if not parts.is_ip:
        for keyword in SUSPICIOUS_HOST_KEYWORDS:
            keyword_count += host.count(keyword)

    features: dict[str, float] = {
        "host_length": float(host_len),
        "domain_length": float(len(sld)),
        "num_dots": float(host.count(".")),
        "num_hyphens": float(host.count("-")),
        "num_digits": float(digits),
        "digit_ratio": float(digits / host_len) if host_len else 0.0,
        "num_subdomains": float(len([s for s in parts.subdomain.split(".") if s])) if parts.subdomain else 0.0,
        "subdomain_length": float(len(parts.subdomain)),
        "longest_label_length": float(max((len(label) for label in labels), default=0)),
        "has_ip": 1.0 if parts.is_ip else 0.0,
        "punycode": 1.0 if any(label.startswith("xn--") for label in labels) else 0.0,
        "tld_length": float(len(parts.suffix)),
        "suspicious_tld": 1.0 if parts.suffix and (parts.suffix in SUSPICIOUS_TLDS or parts.suffix.split(".")[-1] in SUSPICIOUS_TLDS) else 0.0,
        "domain_entropy": round(_shannon_entropy(sld), 6),
        "vowel_ratio": round(sum(ch in VOWELS for ch in letters) / len(letters), 6) if letters else 0.0,
        "max_consonant_run": float(_max_run(host, lambda ch: ch.isalpha() and ch not in VOWELS)),
        "max_digit_run": float(_max_run(host, str.isdigit)),
        "max_repeat_run": float(_max_repeat_run(host)),
        "suspicious_keyword_count": float(keyword_count),
        "brand_outside_official": 1.0 if (not parts.is_ip and brands_outside_official_domain(parts)) else 0.0,
        "shared_hosting_subdomain": 1.0 if (not parts.is_ip and is_shared_hosting_subdomain(parts)) else 0.0,
    }
    return features


def features_to_vector(features: dict[str, float]) -> list[float]:
    """Order a feature dict according to ML_FEATURE_NAMES."""
    return [float(features[name]) for name in ML_FEATURE_NAMES]


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import json
    import sys

    for arg in sys.argv[1:] or ["https://www.paypal.com", "http://paypal-secure-login.verify-account.xyz/signin"]:
        print(arg)
        print(json.dumps(extract_ml_features(arg), indent=2))
