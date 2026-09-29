from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import idna as idna_lib

from backend.config import settings


class URLValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    effective_port: int
    path: str
    query: str
    fragment: str
    had_userinfo: bool
    scheme_assumed: bool
    is_ip: bool


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SCHEME_AUTHORITY_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
_REJECT_BARE_SCHEMES = frozenset({
    "javascript", "data", "file", "ftp", "ftps", "gopher", "ws", "wss",
    "mailto", "vbscript", "blob", "ssh", "telnet", "ldap", "irc", "magnet",
    "tel", "sms", "urn", "cid", "mid", "info", "view-source",
})

_SENSITIVE_PARAM_RE = re.compile(
    r"(?:token|auth|session|sid|key|secret|password|passwd|pwd|pass"
    r"|otp|code|sig|signature|jwt|credential|ticket|nonce|email)",
    re.IGNORECASE,
)

_BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".intranet", ".lan", ".home",
    ".corp", ".home.arpa", ".localdomain",
)
_BLOCKED_EXACT = frozenset({
    "localhost", "metadata", "instance-data", "metadata.google.internal",
})


# ---------------------------------------------------------------------------
# Obfuscated IP parsing
# ---------------------------------------------------------------------------

def _try_parse_obfuscated_ip(
    hostname: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass

    hl = hostname.lower()

    if hl.startswith("0x") and "." not in hl:
        try:
            num = int(hl, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(num)
        except (ValueError, OverflowError):
            pass
        return None

    if hostname.isdigit():
        try:
            num = int(hostname)
            if 0 <= num <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(num)
        except (ValueError, OverflowError):
            pass
        return None

    if "." in hostname:
        result = _try_parse_dotted_mixed(hostname)
        if result is not None:
            return result

    try:
        packed = socket.inet_aton(hostname)
        return ipaddress.IPv4Address(packed)
    except OSError:
        pass

    return None


def _try_parse_dotted_mixed(hostname: str) -> ipaddress.IPv4Address | None:
    parts = hostname.split(".")
    if not 2 <= len(parts) <= 4:
        return None

    values: list[int] = []
    for part in parts:
        if not part:
            return None
        try:
            pl = part.lower()
            if pl.startswith("0x"):
                val = int(pl, 16)
            elif len(part) > 1 and part[0] == "0" and all(c in "01234567" for c in part):
                val = int(part, 8)
            else:
                val = int(part)
        except ValueError:
            return None
        if val < 0:
            return None
        values.append(val)

    try:
        if len(values) == 2:
            if values[0] > 0xFF or values[1] > 0xFFFFFF:
                return None
            num = (values[0] << 24) | values[1]
        elif len(values) == 3:
            if values[0] > 0xFF or values[1] > 0xFF or values[2] > 0xFFFF:
                return None
            num = (values[0] << 24) | (values[1] << 16) | values[2]
        elif len(values) == 4:
            if any(v > 0xFF for v in values):
                return None
            num = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
        else:
            return None
        return ipaddress.IPv4Address(num)
    except (ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def normalize_url(raw: str) -> NormalizedURL:
    raw = raw.strip()
    if not raw:
        raise URLValidationError("INVALID_URL", "URL is empty.")

    if _CONTROL_RE.search(raw):
        raise URLValidationError("INVALID_URL", "URL contains control characters.")

    if len(raw) > settings.MAX_URL_LENGTH:
        raise URLValidationError(
            "URL_TOO_LONG",
            f"URL exceeds the maximum length of {settings.MAX_URL_LENGTH} characters.",
        )

    original = raw
    scheme_assumed = False

    m = _SCHEME_AUTHORITY_RE.match(raw)
    if m:
        scheme_name = m.group(1).lower()
        if scheme_name not in ("http", "https"):
            raise URLValidationError(
                "UNSUPPORTED_PROTOCOL", "Only http and https URLs are supported.",
            )
    else:
        colon_idx = raw.find(":")
        if 0 < colon_idx < 20:
            candidate = raw[:colon_idx].lower()
            if candidate in _REJECT_BARE_SCHEMES:
                raise URLValidationError(
                    "UNSUPPORTED_PROTOCOL", "Only http and https URLs are supported.",
                )
        scheme_assumed = True
        raw = "https://" + raw

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()

    if scheme not in ("http", "https"):
        raise URLValidationError(
            "UNSUPPORTED_PROTOCOL", "Only http and https URLs are supported.",
        )

    had_userinfo = "@" in parts.netloc

    hostname_raw = parts.hostname
    if not hostname_raw:
        raise URLValidationError("INVALID_URL", "URL has no hostname.")

    hostname = hostname_raw.lower()

    if " " in hostname or "\t" in hostname:
        raise URLValidationError("INVALID_URL", "Hostname contains spaces.")

    is_ip = False
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    ip_obj = _try_parse_obfuscated_ip(hostname)
    if ip_obj is not None:
        is_ip = True
        hostname = str(ip_obj)
    else:
        try:
            hostname = idna_lib.encode(hostname, uts46=True).decode("ascii")
        except (idna_lib.core.IDNAError, UnicodeError, UnicodeDecodeError):
            raise URLValidationError("INVALID_URL", "Invalid hostname encoding.")

    try:
        port = parts.port
    except ValueError:
        raise URLValidationError("INVALID_URL", "Invalid port number.")

    default_port = 443 if scheme == "https" else 80
    effective_port = port if port is not None else default_port

    if port is not None and port not in settings.ALLOWED_PORTS:
        raise URLValidationError("BLOCKED_PORT", f"Port {port} is not allowed.")
    if effective_port not in settings.ALLOWED_PORTS:
        raise URLValidationError("BLOCKED_PORT", f"Port {effective_port} is not allowed.")

    check_host_allowed(hostname)

    if is_ip:
        # Late import to avoid circular dependency with ssrf_protection
        from backend.security.ssrf_protection import is_ip_allowed
        if not is_ip_allowed(ip_obj):
            raise URLValidationError(
                "PRIVATE_ADDRESS",
                "URL points to a private or reserved IP address.",
            )

    path = parts.path or "/"
    query = parts.query
    fragment = parts.fragment

    if is_ip and isinstance(ip_obj, ipaddress.IPv6Address):
        host_str = f"[{hostname}]"
    else:
        host_str = hostname

    netloc_str = f"{host_str}:{port}" if port is not None else host_str
    normalized = urlunsplit((scheme, netloc_str, path, query, fragment))

    return NormalizedURL(
        original=original,
        normalized=normalized,
        scheme=scheme,
        hostname=hostname,
        port=port,
        effective_port=effective_port,
        path=path,
        query=query,
        fragment=fragment,
        had_userinfo=had_userinfo,
        scheme_assumed=scheme_assumed,
        is_ip=is_ip,
    )


def check_host_allowed(hostname: str) -> None:
    hl = hostname.lower()

    if hl in _BLOCKED_EXACT:
        raise URLValidationError("BLOCKED_HOST", f"Access to '{hostname}' is not allowed.")

    for suffix in _BLOCKED_SUFFIXES:
        if hl.endswith(suffix):
            raise URLValidationError(
                "BLOCKED_HOST", f"Access to '{hostname}' is not allowed.",
            )

    for blocked in settings.BLOCKED_HOSTNAMES:
        if hl == blocked.lower():
            raise URLValidationError(
                "BLOCKED_HOST", f"Access to '{hostname}' is not allowed.",
            )

    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass

    if "." not in hl:
        raise URLValidationError("BLOCKED_HOST", "Single-label hostnames are not allowed.")


# ---------------------------------------------------------------------------
# URL redaction
# ---------------------------------------------------------------------------

def _redact_params(param_string: str) -> str:
    if not param_string:
        return param_string
    segments: list[str] = []
    for pair in param_string.split("&"):
        eq = pair.find("=")
        if eq >= 0:
            name = pair[:eq]
            if _SENSITIVE_PARAM_RE.search(name):
                segments.append(f"{name}=REDACTED")
                continue
        segments.append(pair)
    return "&".join(segments)


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url

    hostname = parts.hostname or ""
    if not hostname and not parts.netloc:
        return url

    try:
        addr = ipaddress.ip_address(hostname)
        host_str = f"[{hostname}]" if isinstance(addr, ipaddress.IPv6Address) else hostname
    except ValueError:
        host_str = hostname

    try:
        port = parts.port
    except ValueError:
        port = None

    netloc_str = f"{host_str}:{port}" if port is not None else host_str

    query = _redact_params(parts.query)
    fragment = (
        _redact_params(parts.fragment)
        if parts.fragment and "=" in parts.fragment
        else parts.fragment
    )

    return urlunsplit((parts.scheme, netloc_str, parts.path or "", query, fragment))
