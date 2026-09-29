from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpcore
import httpx

from backend.config import settings


class BlockedDestinationError(Exception):
    code = "BLOCKED_DESTINATION"

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class FetchError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        redirect_chain: list[RedirectHop] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.redirect_chain = redirect_chain or []
        super().__init__(message)


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None
    ip: str | None


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    truncated: bool
    content_type: str
    encoding: str | None
    redirect_chain: list[RedirectHop]
    ip: str | None
    elapsed_ms: int
    tls_verified: bool


# ---------------------------------------------------------------------------
# IP allowlist
# ---------------------------------------------------------------------------

_METADATA_IPS = frozenset({
    ipaddress.IPv4Address("169.254.169.254"),
    ipaddress.IPv6Address("fd00:ec2::254"),
})

_NAT64_NET = ipaddress.IPv6Network("64:ff9b::/96")
_TEREDO_NET = ipaddress.IPv6Network("2001::/32")
_SITE_LOCAL_NET = ipaddress.IPv6Network("fec0::/10")


def is_ip_allowed(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, str):
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            return False

    if ip in _METADATA_IPS:
        return False

    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False

    if ip.is_private:
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        return ip.is_global

    # --- IPv6 extended checks ---

    if ip in _SITE_LOCAL_NET:
        return False

    if ip.ipv4_mapped:
        return is_ip_allowed(ip.ipv4_mapped)

    int_val = int(ip)

    # 6to4  (2002::/16) -- bytes 3-6 embed an IPv4 address
    if (int_val >> 112) == 0x2002:
        embedded_v4 = ipaddress.IPv4Address((int_val >> 80) & 0xFFFFFFFF)
        if not is_ip_allowed(embedded_v4):
            return False

    # NAT64  (64:ff9b::/96) -- last 32 bits embed IPv4
    if ip in _NAT64_NET:
        embedded_v4 = ipaddress.IPv4Address(int_val & 0xFFFFFFFF)
        if not is_ip_allowed(embedded_v4):
            return False

    # Teredo (2001:0000::/32) -- server IPv4 in bits 32-63, client (XOR) in bits 96-127
    if ip in _TEREDO_NET:
        server_v4 = ipaddress.IPv4Address((int_val >> 64) & 0xFFFFFFFF)
        client_v4 = ipaddress.IPv4Address((int_val & 0xFFFFFFFF) ^ 0xFFFFFFFF)
        if not is_ip_allowed(server_v4) or not is_ip_allowed(client_v4):
            return False

    # IPv4-compatible (deprecated  ::x.x.x.x  where top 96 bits are zero)
    if (int_val >> 32) == 0 and (int_val & 0xFFFFFFFF) != 0:
        embedded_v4 = ipaddress.IPv4Address(int_val & 0xFFFFFFFF)
        if not is_ip_allowed(embedded_v4):
            return False

    return ip.is_global


# ---------------------------------------------------------------------------
# DNS resolution + validation
# ---------------------------------------------------------------------------

def resolve_and_validate(hostname: str, port: int) -> list[str]:
    from backend.security.validation import URLValidationError, check_host_allowed

    try:
        check_host_allowed(hostname)
    except URLValidationError as exc:
        raise BlockedDestinationError(exc.message) from exc

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError("DNS_FAILURE", f"Could not resolve hostname: {hostname}") from exc

    if not infos:
        raise FetchError("DNS_FAILURE", f"No addresses found for: {hostname}")

    seen: set[str] = set()
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            ips.append(addr)

    for ip_str in ips:
        if not is_ip_allowed(ip_str):
            raise BlockedDestinationError(
                f"Resolved address for '{hostname}' is not allowed.",
            )

    return ips


# ---------------------------------------------------------------------------
# DNS-rebinding-safe network backend
# ---------------------------------------------------------------------------

class _PinnedBackend(httpcore.SyncBackend):
    """Resolves + validates IPs at TCP-connect time to prevent DNS rebinding."""

    def __init__(self) -> None:
        self.connected_ips: dict[tuple[str, int], str] = {}

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.NetworkStream:
        ips = resolve_and_validate(host, port)
        target_ip = ips[0]
        self.connected_ips[(host, port)] = target_ip
        return super().connect_tcp(
            target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def get_ip(self, host: str, port: int) -> str | None:
        return self.connected_ips.get((host, port))


# ---------------------------------------------------------------------------
# Safe fetcher
# ---------------------------------------------------------------------------

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    max_bytes: int | None = None,
    follow_redirects: bool = True,
    max_redirects: int | None = None,
    verify_tls: bool = True,
    timeout: float | None = None,
) -> FetchResult:
    from backend.security.validation import URLValidationError, normalize_url

    if max_bytes is None:
        max_bytes = settings.FETCH_MAX_BYTES
    if max_redirects is None:
        max_redirects = settings.FETCH_MAX_REDIRECTS
    if timeout is None:
        timeout = settings.FETCH_TOTAL_TIMEOUT

    redirect_chain: list[RedirectHop] = []
    current_url = url
    current_method = method
    start = time.monotonic()
    backend = _PinnedBackend()

    for hop in range(max_redirects + 2):
        elapsed = time.monotonic() - start
        remaining = timeout - elapsed
        if remaining <= 0:
            raise FetchError("TIMEOUT", "Total request timeout exceeded.", redirect_chain)

        # --- validate current URL ---
        try:
            nurl = normalize_url(current_url)
        except URLValidationError as exc:
            if exc.code in ("BLOCKED_HOST", "PRIVATE_ADDRESS"):
                raise BlockedDestinationError(exc.message) from exc
            raise FetchError(exc.code, exc.message, redirect_chain) from exc

        # --- fail-fast DNS + IP check ---
        try:
            resolve_and_validate(nurl.hostname, nurl.effective_port)
        except (BlockedDestinationError, FetchError):
            raise

        # --- build a per-hop httpx client so nothing leaks between hops ---
        verify = verify_tls and nurl.scheme == "https"
        transport = httpx.HTTPTransport(verify=verify)
        # Patch the pool's network backend for DNS-rebinding protection.
        # httpcore re-resolves + re-validates at actual connect time.
        transport._pool._network_backend = backend  # type: ignore[attr-defined]

        client = httpx.Client(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                connect=min(settings.FETCH_CONNECT_TIMEOUT, remaining),
                read=min(settings.FETCH_READ_TIMEOUT, remaining),
                write=min(5.0, remaining),
                pool=min(5.0, remaining),
            ),
        )

        try:
            headers = {
                "User-Agent": settings.FETCH_USER_AGENT,
                "Accept": "text/html,*/*;q=0.8",
            }

            with client.stream(current_method, nurl.normalized, headers=headers) as response:
                connected_ip = backend.get_ip(nurl.hostname, nurl.effective_port)

                # --- handle redirects ---
                if response.status_code in _REDIRECT_STATUSES and follow_redirects:
                    location = response.headers.get("location")
                    redirect_chain.append(RedirectHop(
                        url=nurl.normalized,
                        status_code=response.status_code,
                        location=location,
                        ip=connected_ip,
                    ))
                    if hop >= max_redirects:
                        raise FetchError(
                            "TOO_MANY_REDIRECTS",
                            f"Exceeded {max_redirects} redirects.",
                            redirect_chain,
                        )
                    if not location:
                        raise FetchError(
                            "INVALID_URL",
                            "Redirect response missing Location header.",
                            redirect_chain,
                        )
                    current_url = urljoin(nurl.normalized, location)
                    if response.status_code in (301, 302, 303):
                        current_method = "GET"
                    continue

                # --- early Content-Length rejection ---
                cl_header = response.headers.get("content-length")
                if cl_header:
                    try:
                        cl_value = int(cl_header)
                        if cl_value > 10 * max_bytes:
                            raise FetchError(
                                "RESPONSE_TOO_LARGE",
                                f"Response body too large ({cl_value} bytes).",
                                redirect_chain,
                            )
                    except ValueError:
                        pass

                # --- stream body up to max_bytes ---
                truncated = False
                chunks: list[bytes] = []
                bytes_read = 0
                for chunk in response.iter_bytes():
                    space = max_bytes - bytes_read
                    if space <= 0:
                        truncated = True
                        break
                    if len(chunk) > space:
                        chunks.append(chunk[:space])
                        bytes_read += space
                        truncated = True
                        break
                    chunks.append(chunk)
                    bytes_read += len(chunk)

                content = b"".join(chunks)

                # --- collect headers (strip cookie headers) ---
                resp_headers: dict[str, str] = {}
                for name, value in response.headers.items():
                    lname = name.lower()
                    if lname in ("set-cookie", "cookie"):
                        continue
                    resp_headers[lname] = value

                # --- parse content-type / charset ---
                ct_raw = response.headers.get("content-type", "")
                ct_value = ct_raw.split(";")[0].strip() if ct_raw else ""
                encoding: str | None = None
                for part in ct_raw.split(";"):
                    stripped = part.strip().lower()
                    if stripped.startswith("charset="):
                        encoding = stripped[8:].strip("\"' ")
                        break

                elapsed_ms = int((time.monotonic() - start) * 1000)

                return FetchResult(
                    requested_url=url,
                    final_url=nurl.normalized,
                    status_code=response.status_code,
                    headers=resp_headers,
                    content=content,
                    truncated=truncated,
                    content_type=ct_value,
                    encoding=encoding,
                    redirect_chain=redirect_chain,
                    ip=connected_ip,
                    elapsed_ms=elapsed_ms,
                    tls_verified=verify,
                )

        except (BlockedDestinationError, FetchError):
            raise
        except httpx.TimeoutException:
            raise FetchError("TIMEOUT", "Request timed out.", redirect_chain)
        except httpx.ConnectError as exc:
            cause = exc.__cause__
            if isinstance(cause, (ssl.SSLError, ssl.SSLCertVerificationError)):
                raise FetchError("SSL_ERROR", f"TLS/SSL error: {exc}", redirect_chain) from exc
            if cause and "ssl" in str(cause).lower():
                raise FetchError("SSL_ERROR", f"TLS/SSL error: {exc}", redirect_chain) from exc
            raise FetchError("CONNECTION_FAILED", f"Connection failed: {exc}", redirect_chain) from exc
        except socket.gaierror as exc:
            raise FetchError("DNS_FAILURE", "DNS resolution failed.", redirect_chain) from exc
        except Exception as exc:
            raise FetchError("CONNECTION_FAILED", f"Request failed: {exc}", redirect_chain) from exc
        finally:
            client.close()

    raise FetchError(
        "TOO_MANY_REDIRECTS",
        f"Exceeded {max_redirects} redirects.",
        redirect_chain,
    )


# ---------------------------------------------------------------------------
# HTTP -> HTTPS probe
# ---------------------------------------------------------------------------

def probe_http_to_https(hostname: str, port: int | None = None) -> bool | None:
    effective_port = port or 80
    host_str = f"[{hostname}]" if ":" in hostname else hostname
    port_part = f":{effective_port}" if effective_port != 80 else ""
    probe_url = f"http://{host_str}{port_part}/"

    try:
        result = safe_fetch(
            probe_url,
            follow_redirects=False,
            max_bytes=16384,
            timeout=settings.FETCH_CONNECT_TIMEOUT + settings.FETCH_READ_TIMEOUT,
        )
    except (FetchError, BlockedDestinationError):
        return None

    if result.status_code in _REDIRECT_STATUSES:
        location = result.headers.get("location", "")
        if location.lower().startswith("https://"):
            return True
    return False
