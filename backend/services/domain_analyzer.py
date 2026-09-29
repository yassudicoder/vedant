"""
Domain intelligence analyzer for PhishGuard.

Gathers registration data (RDAP / WHOIS), DNS records, ASN information,
popularity ranking (Tranco), and reputation (Google Safe Browsing) for a
given hostname.

All external lookups use timeouts and fail gracefully: when a data source
is unavailable the corresponding field is ``None`` with a human-readable
message. Data is **never** fabricated.

RDAP results are cached in-process for 1 hour to be polite to registries.
Tranco CSV is loaded once and kept in an LRU cache.
"""
from __future__ import annotations

import csv
import ipaddress
import logging
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import dns.resolver
import dns.rdatatype
import dns.reversename
import dns.name
import httpx

from backend.config import settings
from backend.services.common import make_finding, truncate, UNAVAILABLE
from ml.feature_extractor import (
    SHARED_HOSTING_DOMAINS,
    SUSPICIOUS_TLDS,
    parse_host,
    is_shared_hosting_subdomain,
)

try:
    from backend.security.ssrf_protection import resolve_and_validate
except ImportError:  # pragma: no cover - module may not exist yet
    resolve_and_validate = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_SOURCE = "domain_analyzer"

# ------------------------------------------------------------------ #
# RDAP in-memory LRU cache (1 hour TTL)
# ------------------------------------------------------------------ #
_rdap_cache: dict[str, tuple[float, dict | None]] = {}
_RDAP_CACHE_TTL = 3600  # seconds
_RDAP_CACHE_MAX = 512


def _rdap_cache_get(domain: str) -> dict | None:
    entry = _rdap_cache.get(domain)
    if entry is None:
        return None
    ts, data = entry
    if time.monotonic() - ts > _RDAP_CACHE_TTL:
        _rdap_cache.pop(domain, None)
        return None
    return data


def _rdap_cache_put(domain: str, data: dict | None) -> None:
    # Evict oldest entries if cache is full.
    if len(_rdap_cache) >= _RDAP_CACHE_MAX:
        oldest = min(_rdap_cache, key=lambda k: _rdap_cache[k][0])
        _rdap_cache.pop(oldest, None)
    _rdap_cache[domain] = (time.monotonic(), data)


# ------------------------------------------------------------------ #
# Tranco popularity list (loaded once)
# ------------------------------------------------------------------ #
@lru_cache(maxsize=1)
def _load_tranco(path: str, top_n: int) -> dict[str, int] | None:
    """Load Tranco CSV into {domain: rank}. Returns None if file missing."""
    p = Path(path)
    if not p.is_file():
        return None
    ranks: dict[str, int] = {}
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    try:
                        rank = int(row[0])
                    except ValueError:
                        continue
                    domain = row[1].strip().lower()
                    if rank <= top_n and domain:
                        ranks[domain] = rank
    except OSError as exc:
        logger.warning("Failed to load Tranco list from %s: %s", path, exc)
        return None
    return ranks


# ------------------------------------------------------------------ #
# DNS resolution helpers
# ------------------------------------------------------------------ #
def _resolve_dns(hostname: str, timeout: float) -> dict:
    """Resolve A, AAAA, MX, NS, CNAME, SPF, DMARC records."""
    result: dict[str, Any] = {
        "resolves": False,
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "cname": None,
        "has_spf": None,
        "has_dmarc": None,
        "error": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    # A records
    try:
        answers = resolver.resolve(hostname, "A")
        result["a"] = sorted(str(rdata) for rdata in answers)
        result["resolves"] = True
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain does not exist (NXDOMAIN)."
        return result
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as exc:
        result["error"] = truncate(f"DNS resolution failed: {type(exc).__name__}", 200)

    # AAAA records
    try:
        answers = resolver.resolve(hostname, "AAAA")
        result["aaaa"] = sorted(str(rdata) for rdata in answers)
        if result["aaaa"]:
            result["resolves"] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # MX records
    try:
        answers = resolver.resolve(hostname, "MX")
        result["mx"] = sorted(
            truncate(str(rdata.exchange).rstrip("."), 200) for rdata in answers
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # NS records
    try:
        answers = resolver.resolve(hostname, "NS")
        result["ns"] = sorted(
            truncate(str(rdata).rstrip("."), 200) for rdata in answers
        )
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # CNAME
    try:
        answers = resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            result["cname"] = truncate(str(rdata).rstrip("."), 200)
            break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # SPF (TXT record containing "v=spf1")
    try:
        answers = resolver.resolve(hostname, "TXT")
        txt_records = [str(rdata).strip('"') for rdata in answers]
        result["has_spf"] = any("v=spf1" in txt for txt in txt_records)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # DMARC (TXT record at _dmarc.<domain>)
    try:
        dmarc_host = f"_dmarc.{hostname}"
        answers = resolver.resolve(dmarc_host, "TXT")
        txt_records = [str(rdata).strip('"') for rdata in answers]
        result["has_dmarc"] = any("v=dmarc1" in txt.lower() for txt in txt_records)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        if result["has_dmarc"] is None:
            result["has_dmarc"] = False

    return result


# ------------------------------------------------------------------ #
# RDAP registration lookup
# ------------------------------------------------------------------ #
def _fetch_rdap(domain: str) -> dict | None:
    """Fetch RDAP data for *domain*. Returns parsed JSON or None."""
    cached = _rdap_cache_get(domain)
    if cached is not None:
        return cached

    url = settings.RDAP_BOOTSTRAP_URL + domain
    try:
        with httpx.Client(
            timeout=httpx.Timeout(settings.RDAP_TIMEOUT, connect=settings.FETCH_CONNECT_TIMEOUT),
            follow_redirects=True,
            max_redirects=5,
            trust_env=False,
        ) as client:
            resp = client.get(url, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status_code == 200:
                data = resp.json()
                _rdap_cache_put(domain, data)
                return data
            # 404 = domain not in RDAP, cache as None
            if resp.status_code == 404:
                _rdap_cache_put(domain, None)
            return None
    except (httpx.HTTPError, httpx.InvalidURL, ValueError, KeyError) as exc:
        logger.debug("RDAP lookup failed for %s: %s", domain, exc)
        return None


def _parse_rdap_registration(rdap_data: dict | None) -> dict:
    """Extract registration info from RDAP JSON."""
    result: dict[str, Any] = {
        "available": False,
        "source": None,
        "created": None,
        "updated": None,
        "expires": None,
        "domain_age_days": None,
        "days_until_expiry": None,
        "registrar": None,
        "statuses": [],
        "message": "Domain registration information unavailable.",
    }

    if rdap_data is None:
        return result

    result["available"] = True
    result["source"] = "rdap"
    now = datetime.now(timezone.utc)

    # Parse events
    events = rdap_data.get("events", [])
    for event in events:
        action = (event.get("eventAction") or "").lower()
        date_str = event.get("eventDate")
        if not date_str:
            continue
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        if action == "registration":
            result["created"] = dt.isoformat()
            age = (now - dt).days
            result["domain_age_days"] = max(age, 0)
        elif action == "last changed":
            result["updated"] = dt.isoformat()
        elif action == "expiration":
            result["expires"] = dt.isoformat()
            days_left = (dt - now).days
            result["days_until_expiry"] = days_left

    # Parse registrar from entities
    entities = rdap_data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            # Try vcard fn field
            vcard_array = entity.get("vcardArray")
            if vcard_array and len(vcard_array) >= 2:
                for field in vcard_array[1]:
                    if len(field) >= 4 and field[0] == "fn":
                        result["registrar"] = truncate(str(field[3]), 200)
                        break
            # Fallback to handle/name
            if not result["registrar"]:
                name = entity.get("handle") or entity.get("ldhName")
                if name:
                    result["registrar"] = truncate(str(name), 200)
            break

    # Statuses
    statuses = rdap_data.get("status", [])
    result["statuses"] = [truncate(str(s), 100) for s in statuses[:20]]

    if result["available"]:
        result["message"] = None

    return result


def _whois_fallback(domain: str) -> dict:
    """Use python-whois as RDAP fallback if enabled."""
    result: dict[str, Any] = {
        "available": False,
        "source": None,
        "created": None,
        "updated": None,
        "expires": None,
        "domain_age_days": None,
        "days_until_expiry": None,
        "registrar": None,
        "statuses": [],
        "message": "Domain registration information unavailable.",
    }

    if not settings.ENABLE_WHOIS_FALLBACK:
        return result

    try:
        import whois  # python-whois
    except ImportError:
        logger.debug("python-whois not available for fallback")
        return result

    try:
        w = whois.whois(domain)
    except Exception as exc:
        logger.debug("WHOIS fallback failed for %s: %s", domain, exc)
        return result

    if w is None or not w.domain_name:
        return result

    result["available"] = True
    result["source"] = "whois"
    now = datetime.now(timezone.utc)

    # creation_date can be a list or a datetime
    created = w.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if isinstance(created, datetime):
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        result["created"] = created.isoformat()
        result["domain_age_days"] = max((now - created).days, 0)

    updated = w.updated_date
    if isinstance(updated, list):
        updated = updated[0] if updated else None
    if isinstance(updated, datetime):
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        result["updated"] = updated.isoformat()

    expires = w.expiration_date
    if isinstance(expires, list):
        expires = expires[0] if expires else None
    if isinstance(expires, datetime):
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        result["expires"] = expires.isoformat()
        result["days_until_expiry"] = (expires - now).days

    if w.registrar:
        result["registrar"] = truncate(str(w.registrar), 200)

    if w.status:
        statuses = w.status if isinstance(w.status, list) else [w.status]
        result["statuses"] = [truncate(str(s), 100) for s in statuses[:20]]

    result["message"] = None
    return result


# ------------------------------------------------------------------ #
# ASN lookup via Team Cymru DNS
# ------------------------------------------------------------------ #
def _lookup_asn(ip: str) -> dict | None:
    """Query Team Cymru DNS for ASN info. Returns None on failure."""
    if not settings.ENABLE_ASN_LOOKUP:
        return None

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.DNS_TIMEOUT
    resolver.timeout = settings.DNS_TIMEOUT

    try:
        if isinstance(addr, ipaddress.IPv4Address):
            # Reverse the IP octets
            octets = str(addr).split(".")
            query_name = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
        else:
            # IPv6: expand and reverse nibbles
            expanded = addr.exploded.replace(":", "")
            query_name = ".".join(reversed(expanded)) + ".origin6.asn.cymru.com"

        answers = resolver.resolve(query_name, "TXT")
        # Response: "ASN | prefix | CC | registry | date"
        txt = str(list(answers)[0]).strip('"')
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) < 5:
            return None

        asn_str = parts[0].strip()
        # May have multiple ASNs space-separated; take first
        asn_num = asn_str.split()[0] if asn_str else ""

        asn_result: dict[str, Any] = {
            "asn": truncate(asn_num, 20),
            "prefix": truncate(parts[1].strip(), 50),
            "country": truncate(parts[2].strip().upper(), 10),
            "registry": truncate(parts[3].strip(), 30),
            "as_name": None,
        }

        # Look up AS name
        if asn_num and asn_num.isdigit():
            try:
                name_answers = resolver.resolve(f"AS{asn_num}.asn.cymru.com", "TXT")
                name_txt = str(list(name_answers)[0]).strip('"')
                name_parts = [p.strip() for p in name_txt.split("|")]
                if len(name_parts) >= 5:
                    asn_result["as_name"] = truncate(name_parts[4].strip(), 200)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                    dns.exception.DNSException):
                pass

        return asn_result

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException) as exc:
        logger.debug("ASN lookup failed for %s: %s", ip, exc)
        return None


# ------------------------------------------------------------------ #
# Popularity lookup (Tranco)
# ------------------------------------------------------------------ #
def _lookup_popularity(registered_domain: str) -> dict:
    """Check Tranco ranking for the domain."""
    result: dict[str, Any] = {
        "available": False,
        "rank": None,
        "source": f"Tranco top-{settings.TRANCO_TOP_N}",
        "message": "Popularity list not installed.",
    }

    ranks = _load_tranco(settings.TRANCO_LIST_PATH, settings.TRANCO_TOP_N)
    if ranks is None:
        return result

    result["available"] = True
    domain_lower = registered_domain.lower()
    rank = ranks.get(domain_lower)
    if rank is not None:
        result["rank"] = rank
        result["message"] = f"Ranked #{rank} in Tranco top-{settings.TRANCO_TOP_N} list."
    else:
        result["rank"] = None
        result["message"] = f"Not found in Tranco top-{settings.TRANCO_TOP_N} list."

    return result


# ------------------------------------------------------------------ #
# Reputation (Google Safe Browsing v4)
# ------------------------------------------------------------------ #
def _check_reputation(url_to_check: str) -> dict:
    """Query Google Safe Browsing v4 if configured."""
    result: dict[str, Any] = {
        "configured": False,
        "provider": None,
        "listed": None,
        "threats": [],
        "message": "No reputation API configured.",
    }

    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return result

    result["configured"] = True
    result["provider"] = "Google Safe Browsing"

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    body = {
        "client": {"clientId": "phishguard", "clientVersion": settings.APP_VERSION},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}],
        },
    }

    try:
        with httpx.Client(
            timeout=httpx.Timeout(settings.RDAP_TIMEOUT, connect=settings.FETCH_CONNECT_TIMEOUT),
            trust_env=False,
        ) as client:
            resp = client.post(endpoint, json=body)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    result["listed"] = True
                    result["threats"] = [
                        truncate(m.get("threatType", "UNKNOWN"), 100)
                        for m in matches[:10]
                    ]
                    result["message"] = f"Listed in Google Safe Browsing ({len(matches)} threat(s))."
                else:
                    result["listed"] = False
                    result["message"] = "Not listed in Google Safe Browsing."
            else:
                result["listed"] = None
                result["message"] = truncate(
                    f"Google Safe Browsing API returned HTTP {resp.status_code}.", 200
                )
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("Safe Browsing check failed: %s", exc)
        result["listed"] = None
        result["message"] = truncate(f"Reputation check failed: {type(exc).__name__}.", 200)

    return result


# ------------------------------------------------------------------ #
# Main analyzer
# ------------------------------------------------------------------ #
def analyze_domain(
    hostname: str,
    *,
    resolved_ips: list[str] | None = None,
) -> dict:
    """
    Analyse domain registration, DNS, ASN, popularity, and reputation.

    Parameters
    ----------
    hostname : str
        The hostname to analyse.
    resolved_ips : list[str] or None
        Pre-resolved IP addresses (from the fetch stage). If ``None``,
        DNS resolution is performed here.

    Returns
    -------
    dict
        Domain analysis conforming to contract section 3.6.
    """
    findings: list[dict] = []
    status = "ok"

    host_parts = parse_host(hostname)
    registered_domain = host_parts.registered_domain or hostname
    tld = host_parts.suffix

    # --- DNS resolution ---------------------------------------------------- #
    dns_result = _resolve_dns(hostname, settings.DNS_TIMEOUT)

    # Merge pre-resolved IPs into A/AAAA if not already present.
    if resolved_ips:
        for ip_str in resolved_ips:
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    if ip_str not in dns_result["a"]:
                        dns_result["a"].append(ip_str)
                else:
                    if ip_str not in dns_result["aaaa"]:
                        dns_result["aaaa"].append(ip_str)
                dns_result["resolves"] = True
            except ValueError:
                pass

    if not dns_result["resolves"]:
        findings.append(make_finding(
            "domain.no_dns", "strong", "domain",
            "Domain does not resolve to any IP address.",
            detail=truncate(dns_result.get("error"), 200),
            points=20, source=_SOURCE,
        ))

    # Pick a primary IP for ASN lookup.
    ip_address_str: str | None = None
    if dns_result["a"]:
        ip_address_str = dns_result["a"][0]
    elif dns_result["aaaa"]:
        ip_address_str = dns_result["aaaa"][0]
    elif resolved_ips:
        ip_address_str = resolved_ips[0]

    # --- Registration (RDAP + fallback WHOIS) ------------------------------ #
    registration: dict
    if not host_parts.is_ip and registered_domain:
        rdap_data = _fetch_rdap(registered_domain)
        registration = _parse_rdap_registration(rdap_data)

        # Fallback to WHOIS if RDAP unavailable.
        if not registration["available"]:
            registration = _whois_fallback(registered_domain)
    else:
        registration = {
            "available": False, "source": None, "created": None,
            "updated": None, "expires": None, "domain_age_days": None,
            "days_until_expiry": None, "registrar": None, "statuses": [],
            "message": "Registration data not applicable for IP addresses.",
        }

    # Registration-based findings.
    if registration["available"]:
        age = registration.get("domain_age_days")
        if age is not None and age < 30:
            findings.append(make_finding(
                "domain.young", "medium", "domain",
                f"Domain was registered only {age} day(s) ago.",
                points=15, source=_SOURCE,
            ))
        elif age is not None and age < 90:
            findings.append(make_finding(
                "domain.fairly_young", "low", "domain",
                f"Domain was registered {age} day(s) ago (less than 90 days).",
                points=6, source=_SOURCE,
            ))
        elif age is not None and age > 365:
            findings.append(make_finding(
                "domain.established", "positive", "domain",
                f"Domain has been registered for {age} days (over 1 year).",
                points=-6, source=_SOURCE,
            ))

        expiry_days = registration.get("days_until_expiry")
        if expiry_days is not None and expiry_days < 30:
            findings.append(make_finding(
                "domain.expiring_soon", "low", "domain",
                f"Domain expires in {expiry_days} day(s).",
                points=5, source=_SOURCE,
            ))
    else:
        if not host_parts.is_ip:
            status = "partial"

    # --- ASN --------------------------------------------------------------- #
    asn_result: dict | None = None
    if ip_address_str and settings.ENABLE_ASN_LOOKUP:
        asn_result = _lookup_asn(ip_address_str)

    # --- Popularity -------------------------------------------------------- #
    popularity = _lookup_popularity(registered_domain)

    if popularity["available"] and popularity["rank"] is not None:
        rank = popularity["rank"]
        if rank <= 1000:
            findings.append(make_finding(
                "domain.highly_popular", "positive", "domain",
                f"Domain is ranked #{rank} in the Tranco top list (highly popular).",
                points=-12, source=_SOURCE,
            ))
        elif rank <= 10000:
            findings.append(make_finding(
                "domain.popular", "positive", "domain",
                f"Domain is ranked #{rank} in the Tranco top list.",
                points=-8, source=_SOURCE,
            ))
        elif rank <= 100000:
            findings.append(make_finding(
                "domain.moderately_popular", "positive", "domain",
                f"Domain is ranked #{rank} in the Tranco top list.",
                points=-4, source=_SOURCE,
            ))

    # --- Reputation -------------------------------------------------------- #
    reputation_url = f"https://{hostname}/"
    reputation = _check_reputation(reputation_url)

    if reputation["listed"]:
        threats_str = ", ".join(reputation["threats"][:5])
        findings.append(make_finding(
            "domain.safe_browsing_listed", "strong", "reputation",
            f"Domain is listed in Google Safe Browsing: {truncate(threats_str, 200)}.",
            points=30, source=_SOURCE,
        ))
    elif reputation["configured"] and reputation["listed"] is False:
        findings.append(make_finding(
            "domain.safe_browsing_clean", "positive", "reputation",
            "Domain is not listed in Google Safe Browsing.",
            points=-3, source=_SOURCE,
        ))

    # --- Shared hosting ---------------------------------------------------- #
    shared_hosting = is_shared_hosting_subdomain(host_parts)
    if shared_hosting:
        findings.append(make_finding(
            "domain.shared_hosting", "low", "domain",
            f"Domain is on a shared hosting platform ({registered_domain}).",
            points=6, source=_SOURCE,
        ))

    # --- Suspicious TLD ---------------------------------------------------- #
    if tld and (tld in SUSPICIOUS_TLDS or tld.split(".")[-1] in SUSPICIOUS_TLDS):
        findings.append(make_finding(
            "domain.suspicious_tld", "low", "domain",
            f"Domain uses a TLD (.{tld}) frequently associated with abuse.",
            points=6, source=_SOURCE,
        ))

    # --- DNS findings ------------------------------------------------------ #
    if dns_result["has_spf"] is False and dns_result["resolves"]:
        findings.append(make_finding(
            "domain.no_spf", "info", "domain",
            "No SPF record found for domain.",
            source=_SOURCE,
        ))

    if dns_result["has_dmarc"] is False and dns_result["resolves"]:
        findings.append(make_finding(
            "domain.no_dmarc", "info", "domain",
            "No DMARC record found for domain.",
            source=_SOURCE,
        ))

    # --- Determine overall status ------------------------------------------ #
    if not dns_result["resolves"] and not registration["available"]:
        status = "unavailable"

    return {
        "status": status,
        "domain": registered_domain,
        "hostname": hostname,
        "tld": tld,
        "registration": registration,
        "dns": dns_result,
        "ip_address": ip_address_str,
        "asn": asn_result,
        "popularity": popularity,
        "reputation": reputation,
        "shared_hosting": shared_hosting,
        "findings": findings,
    }
