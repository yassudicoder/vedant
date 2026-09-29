"""TLS/certificate analysis for PhishGuard."""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any

import certifi
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from backend.config import settings
from backend.services.common import make_finding, UNAVAILABLE
from backend.security.ssrf_protection import (
    resolve_and_validate,
    FetchError,
    BlockedDestinationError,
)

SOURCE = "tls_analyzer"

FREE_DV_ISSUERS: tuple[str, ...] = (
    "let's encrypt",
    "letsencrypt",
    "r3", "r4", "r10", "r11",
    "e5", "e6", "e7", "e8", "e9",
    "zerossl",
    "buypass",
    "google trust services",
)

FREE_DV_ORGS: frozenset[str] = frozenset({
    "let's encrypt",
    "zerossl",
    "buypass as",
    "buypass",
    "google trust services llc",
})

_NOTE = (
    "HTTPS protects the connection but does not guarantee "
    "that the website itself is trustworthy."
)


def _empty_result(
    status: str = "unavailable",
    message: str | None = None,
    https_available: bool | None = None,
    findings: list[dict] | None = None,
) -> dict:
    return {
        "status": status,
        "message": message,
        "https_available": https_available,
        "certificate_valid": None,
        "validation_error": None,
        "hostname_match": None,
        "issuer": {"common_name": None, "organization": None},
        "subject": {"common_name": None, "organization": None},
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "certificate_age_days": None,
        "tls_version": None,
        "cipher": None,
        "self_signed": None,
        "issuer_category": "unknown",
        "mixed_content": {"detected": False, "count": 0, "examples": []},
        "note": _NOTE,
        "findings": findings or [],
    }


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _parse_der(der_bytes: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der_bytes)

    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    subject_org = _name_attr(cert.subject, NameOID.ORGANIZATION_NAME)

    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for dns_name in ext.value.get_values_for_type(x509.DNSName):
            san.append(dns_name)
        for ip_addr in ext.value.get_values_for_type(x509.IPAddress):
            san.append(str(ip_addr))
    except (x509.ExtensionNotFound, Exception):
        pass

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    days_until_expiry = (not_after - now).days
    certificate_age_days = (now - not_before).days

    self_signed = cert.issuer == cert.subject

    issuer_category = "unknown"
    combined = ((issuer_cn or "") + " " + (issuer_org or "")).lower()
    org_lower = (issuer_org or "").lower().strip()

    if any(token in combined for token in FREE_DV_ISSUERS):
        issuer_category = "free_dv"
    elif org_lower in FREE_DV_ORGS:
        issuer_category = "free_dv"
    elif issuer_org and not self_signed:
        issuer_category = "commercial"

    return {
        "issuer": {"common_name": issuer_cn, "organization": issuer_org},
        "subject": {"common_name": subject_cn, "organization": subject_org},
        "san": san[:25],
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_until_expiry": days_until_expiry,
        "certificate_age_days": certificate_age_days,
        "self_signed": self_signed,
        "issuer_category": issuer_category,
    }


def _hostname_matches(hostname: str, san_list: list[str], subject_cn: str | None) -> bool:
    names = list(san_list)
    if subject_cn and subject_cn not in names:
        names.append(subject_cn)
    host = hostname.lower()
    for pattern in names:
        p = pattern.lower()
        if p == host:
            return True
        if p.startswith("*."):
            suffix = p[2:]
            if host.endswith(suffix) and host.count(".") == p.count("."):
                return True
    return False


def _connect(
    ip: str,
    port: int,
    hostname: str,
    verify: bool,
    timeout: float,
) -> tuple[ssl.SSLSocket, bytes | None]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_verify_locations(certifi.where())
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        raw.close()
        raise

    der = ssock.getpeercert(binary_form=True)
    return ssock, der


def analyze_tls(
    hostname: str,
    port: int = 443,
    *,
    https_requested: bool = True,
) -> dict:
    if not https_requested:
        return {
            **_empty_result(
                status="ok",
                https_available=None,
                findings=[
                    make_finding(
                        "tls.no_https", "low", "tls",
                        "The URL was requested over plain HTTP without encryption.",
                        points=5, source=SOURCE,
                    )
                ],
            ),
            "message": None,
        }

    timeout = settings.FETCH_CONNECT_TIMEOUT

    try:
        ips = resolve_and_validate(hostname, port)
    except (FetchError, BlockedDestinationError) as exc:
        return _empty_result(
            status="unavailable",
            message=f"Could not resolve hostname: {exc.message}",
            https_available=None,
        )
    except Exception as exc:
        return _empty_result(
            status="error",
            message=f"DNS resolution error: {str(exc)[:200]}",
            https_available=None,
        )

    if not ips:
        return _empty_result(
            status="unavailable",
            message="No IP addresses resolved for hostname.",
            https_available=None,
        )

    ip = ips[0]
    tls_version: str | None = None
    cipher: str | None = None
    validation_error: str | None = None
    certificate_valid: bool | None = None
    hostname_match: bool | None = None
    cert_info: dict[str, Any] = {}

    try:
        ssock, der = _connect(ip, port, hostname, verify=True, timeout=timeout)
        certificate_valid = True
        tls_version = ssock.version()
        ci = ssock.cipher()
        cipher = ci[0] if ci else None
        ssock.close()

        if der:
            cert_info = _parse_der(der)
            hostname_match = _hostname_matches(
                hostname,
                cert_info.get("san", []),
                cert_info.get("subject", {}).get("common_name"),
            )

    except ssl.SSLCertVerificationError as exc:
        validation_error = str(exc)[:300]
        certificate_valid = False
        try:
            ssock, der = _connect(ip, port, hostname, verify=False, timeout=timeout)
            tls_version = ssock.version()
            ci = ssock.cipher()
            cipher = ci[0] if ci else None
            ssock.close()
            if der:
                cert_info = _parse_der(der)
                hostname_match = _hostname_matches(
                    hostname,
                    cert_info.get("san", []),
                    cert_info.get("subject", {}).get("common_name"),
                )
        except Exception:
            pass

    except (socket.timeout, TimeoutError):
        return _empty_result(
            status="unavailable",
            message="TLS connection timed out.",
            https_available=False,
        )

    except ConnectionRefusedError:
        return _empty_result(
            status="ok",
            https_available=False,
            findings=[
                make_finding(
                    "tls.no_https", "low", "tls",
                    "HTTPS connection was refused on the expected port.",
                    points=5, source=SOURCE,
                )
            ],
        )

    except OSError as exc:
        if "refused" in str(exc).lower():
            return _empty_result(
                status="ok",
                https_available=False,
                findings=[
                    make_finding(
                        "tls.no_https", "low", "tls",
                        "HTTPS is not available on this host.",
                        points=5, source=SOURCE,
                    )
                ],
            )
        return _empty_result(
            status="unavailable",
            message=f"TLS connection failed: {str(exc)[:200]}",
            https_available=None,
        )

    except Exception as exc:
        return _empty_result(
            status="error",
            message=f"Unexpected TLS error: {str(exc)[:200]}",
            https_available=None,
        )

    # --- Findings ---
    findings: list[dict] = []

    self_signed = cert_info.get("self_signed")
    days_until_expiry = cert_info.get("days_until_expiry")

    if self_signed:
        findings.append(make_finding(
            "tls.self_signed", "strong", "tls",
            "Certificate is self-signed and will not be trusted by browsers.",
            points=25, source=SOURCE,
        ))

    if certificate_valid is False and not self_signed:
        findings.append(make_finding(
            "tls.cert_invalid", "strong", "tls",
            "Certificate failed validation.",
            detail=validation_error,
            points=22, source=SOURCE,
        ))

    if hostname_match is False:
        findings.append(make_finding(
            "tls.hostname_mismatch", "strong", "tls",
            "Certificate does not match the requested hostname.",
            detail=(
                f"Hostname: {hostname}, Subject: "
                f"{cert_info.get('subject', {}).get('common_name', 'N/A')}"
            ),
            points=22, source=SOURCE,
        ))

    if days_until_expiry is not None:
        if days_until_expiry < 0:
            findings.append(make_finding(
                "tls.cert_expired", "strong", "tls",
                f"Certificate expired {abs(days_until_expiry)} days ago.",
                detail=f"Expiry: {cert_info.get('not_after', 'N/A')}",
                points=25, source=SOURCE,
            ))
        elif days_until_expiry <= 14:
            findings.append(make_finding(
                "tls.cert_expiring_soon", "low", "tls",
                f"Certificate expires in {days_until_expiry} days.",
                detail=f"Expiry: {cert_info.get('not_after', 'N/A')}",
                points=4, source=SOURCE,
            ))

    if certificate_valid and not self_signed:
        findings.append(make_finding(
            "tls.valid_certificate", "positive", "tls",
            "Valid TLS certificate verified.",
            detail=f"Issuer: {cert_info.get('issuer', {}).get('organization', 'N/A')}",
            points=-3, source=SOURCE,
        ))

    return {
        "status": "ok",
        "https_available": True,
        "certificate_valid": certificate_valid,
        "validation_error": validation_error,
        "hostname_match": hostname_match,
        "issuer": cert_info.get("issuer", {"common_name": None, "organization": None}),
        "subject": cert_info.get("subject", {"common_name": None, "organization": None}),
        "san": cert_info.get("san", []),
        "not_before": cert_info.get("not_before"),
        "not_after": cert_info.get("not_after"),
        "days_until_expiry": days_until_expiry,
        "certificate_age_days": cert_info.get("certificate_age_days"),
        "tls_version": tls_version,
        "cipher": cipher,
        "self_signed": self_signed,
        "issuer_category": cert_info.get("issuer_category", "unknown"),
        "mixed_content": {"detected": False, "count": 0, "examples": []},
        "note": _NOTE,
        "findings": findings,
    }
