"""
Webpage structure and content analyzer for PhishGuard.

Parses fetched HTML to extract security-relevant signals: forms, links,
iframes, scripts, hidden elements, keyword indicators, meta-refresh/JS
redirects, mixed content, and structural anomalies.

All attacker-controlled text is truncated with ``truncate()`` before storage.
Raw HTML and form values are never stored or returned.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Comment

from backend.config import settings
from backend.services.common import make_finding, truncate, UNAVAILABLE
from ml.feature_extractor import (
    BRAND_OFFICIAL_DOMAINS,
    hostname_from_url,
    parse_host,
)

try:
    from backend.security.ssrf_protection import FetchResult, FetchError
except ImportError:  # pragma: no cover - module may not exist yet
    FetchResult = None  # type: ignore[assignment,misc]
    FetchError = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Status codes that indicate access is restricted.
_RESTRICTED_CODES: frozenset[int] = frozenset({401, 403, 407, 429, 451, 503})

# Bot-challenge detection: common phrases in short challenge pages.
_BOT_CHALLENGE_MARKERS: tuple[str, ...] = (
    "checking your browser",
    "just a moment",
    "verify you are human",
    "enable javascript and cookies",
    "ray id",
    "attention required",
    "access denied",
    "please wait while we verify",
    "ddos protection by",
    "cf-browser-verification",
    "challenge-platform",
)

# Suspicious inline-script patterns.
_SUSPICIOUS_JS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"\beval\s*\(", "description": "Dynamic code execution (eval)"},
    {"pattern": r"\bdocument\.write\s*\(", "description": "Dynamic HTML injection (document.write)"},
    {"pattern": r"\batob\s*\(", "description": "Base64 decoding (atob)"},
    {"pattern": r"\bescape\s*\(", "description": "String escaping (escape)"},
    {"pattern": r"\bunescape\s*\(", "description": "String unescaping (unescape)"},
    {"pattern": r"\bfromCharCode\b", "description": "Character code conversion (fromCharCode)"},
    {"pattern": r"\bsetTimeout\s*\(\s*['\"]", "description": "String-based setTimeout"},
    {"pattern": r"\bwindow\.location\s*[=]", "description": "JavaScript redirect via window.location"},
    {"pattern": r"\blocation\.href\s*[=]", "description": "JavaScript redirect via location.href"},
    {"pattern": r"\blocation\.replace\s*\(", "description": "JavaScript redirect via location.replace"},
]

# Keywords for phishing indicators.
_LOGIN_TERMS: tuple[str, ...] = (
    "log in", "login", "log-in", "sign in", "signin", "sign-in",
    "username", "password", "credential", "authenticate", "verification code",
    "verify your identity", "confirm your account", "enter your password",
    "security check", "one-time password", "otp",
)
_URGENCY_TERMS: tuple[str, ...] = (
    "immediately", "urgent", "expire", "suspended", "unauthorized",
    "limited time", "act now", "verify now", "update now", "confirm now",
    "within 24 hours", "within 48 hours", "account will be",
    "your account has been", "unusual activity", "security alert",
    "action required",
)
_PAYMENT_TERMS: tuple[str, ...] = (
    "credit card", "debit card", "card number", "cvv", "expiry date",
    "billing address", "bank account", "routing number", "ssn",
    "social security", "payment method", "wire transfer", "bitcoin",
    "cryptocurrency", "wallet address",
)

# Content types we analyze.
_HTML_CONTENT_TYPES: frozenset[str] = frozenset({
    "text/html", "application/xhtml+xml",
})


def _is_external(href: str, page_host: str, page_registered: str) -> bool:
    """Return True if *href* points to a host outside the page's registered domain."""
    if not href:
        return False
    host = hostname_from_url(href)
    if not host:
        return False
    parts = parse_host(host)
    rd = parts.registered_domain
    return rd != "" and rd != page_registered


def _is_null_or_fragment(href: str | None) -> bool:
    """Return True for null, empty, '#'-only, or javascript: hrefs."""
    if href is None:
        return True
    href = href.strip()
    if not href or href == "#" or href.startswith("javascript:"):
        return True
    return False


def _detect_bot_challenge(text: str) -> bool:
    """Return True if the visible text looks like a bot-challenge page."""
    lower = text.lower()
    matches = sum(1 for marker in _BOT_CHALLENGE_MARKERS if marker in lower)
    return matches >= 2


def _extract_meta_refresh(soup: BeautifulSoup) -> dict | None:
    """Extract meta http-equiv=refresh URL and delay."""
    for meta in soup.find_all("meta", attrs={"http-equiv": True}):
        if meta.get("http-equiv", "").lower() == "refresh":
            content = meta.get("content", "")
            if not content:
                continue
            # Format: "seconds; url=..." or just "seconds"
            match = re.match(r"(\d+)\s*;\s*url\s*=\s*['\"]?\s*(.+?)\s*['\"]?\s*$", content, re.IGNORECASE)
            if match:
                return {"delay": int(match.group(1)), "url": truncate(match.group(2), 500)}
            # Delay-only (refresh to same page)
            match_delay = re.match(r"(\d+)\s*$", content.strip())
            if match_delay:
                return {"delay": int(match_delay.group(1)), "url": None}
    return None


def _detect_js_redirect(soup: BeautifulSoup) -> bool:
    """Return True if inline scripts contain redirect patterns."""
    redirect_patterns = [
        r"\bwindow\.location\s*[=]",
        r"\blocation\.href\s*[=]",
        r"\blocation\.replace\s*\(",
        r"\bwindow\.navigate\s*\(",
        r"\blocation\.assign\s*\(",
    ]
    for script in soup.find_all("script"):
        text = script.string or ""
        for pat in redirect_patterns:
            if re.search(pat, text):
                return True
    return False


def _content_type_base(ct: str) -> str:
    """Return content type without charset or params."""
    return ct.split(";")[0].strip().lower()


def analyze_webpage(
    fetch: FetchResult | None,  # type: ignore[name-defined]
    *,
    page_url: str,
    fetch_error: FetchError | None = None,  # type: ignore[name-defined]
) -> dict:
    """
    Analyse the fetched HTML of a webpage for phishing signals.

    Parameters
    ----------
    fetch : FetchResult or None
        The fetched page content. ``None`` when the page could not be fetched.
    page_url : str
        The URL of the page being analysed (used for relative URL resolution).
    fetch_error : FetchError or None
        If the fetch failed, the error object with code/message.

    Returns
    -------
    dict
        Analysis results conforming to contract section 3.4.
    """
    findings: list[dict] = []

    # --- No fetch result --------------------------------------------------- #
    if fetch is None:
        msg = "Webpage content unavailable."
        if fetch_error is not None:
            msg = truncate(f"Webpage could not be fetched: {fetch_error.message}", 300) or msg
        return _empty_result(status="unavailable", message=msg, findings=findings)

    http_status = fetch.status_code
    content_type_raw = fetch.content_type or ""
    content_type = _content_type_base(content_type_raw)

    # --- Restricted status ------------------------------------------------- #
    if http_status in _RESTRICTED_CODES:
        return _empty_result(
            status="restricted",
            message="Access restricted - PhishGuard does not bypass access controls.",
            http_status=http_status,
            content_type=truncate(content_type_raw, 100),
            findings=findings,
        )

    # --- Non-HTML content -------------------------------------------------- #
    if content_type not in _HTML_CONTENT_TYPES:
        return _empty_result(
            status="ok",
            message=truncate(f"Content is {content_type}, not HTML. Structural analysis skipped.", 300),
            http_status=http_status,
            content_type=truncate(content_type_raw, 100),
            bytes_analyzed=len(fetch.content),
            truncated=fetch.truncated,
            findings=findings,
        )

    # --- Decode HTML ------------------------------------------------------- #
    encoding = fetch.encoding or "utf-8"
    try:
        html = fetch.content.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):
        html = fetch.content.decode("utf-8", errors="replace")

    bytes_analyzed = len(fetch.content)

    # --- Parse ------------------------------------------------------------- #
    soup = BeautifulSoup(html, "html.parser")

    # --- Bot challenge detection ------------------------------------------- #
    visible_text = soup.get_text(separator=" ", strip=True)
    if http_status in _RESTRICTED_CODES or _detect_bot_challenge(visible_text):
        if http_status in _RESTRICTED_CODES or (len(visible_text) < 2000 and _detect_bot_challenge(visible_text)):
            return _empty_result(
                status="restricted",
                message="Access restricted - PhishGuard does not bypass access controls.",
                http_status=http_status,
                content_type=truncate(content_type_raw, 100),
                bytes_analyzed=bytes_analyzed,
                truncated=fetch.truncated,
                findings=findings,
            )

    # --- Page host info for relative URL decisions ------------------------- #
    page_host_parts = parse_host(hostname_from_url(page_url))
    page_host = page_host_parts.hostname
    page_registered = page_host_parts.registered_domain

    # --- Title & meta ------------------------------------------------------ #
    title_tag = soup.find("title")
    title = truncate(title_tag.get_text(strip=True), 300) if title_tag else None

    meta_desc_tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    meta_description = None
    if meta_desc_tag:
        meta_description = truncate(meta_desc_tag.get("content", ""), 500)

    lang_tag = soup.find("html")
    language = None
    if lang_tag:
        language = truncate(lang_tag.get("lang"), 20)

    # --- Favicon ----------------------------------------------------------- #
    favicon_info = {"present": False, "href": None, "external": False, "domain": None}
    for link_tag in soup.find_all("link", rel=True):
        rels = [r.lower() for r in (link_tag.get("rel") or [])]
        if "icon" in rels or "shortcut" in rels:
            href = link_tag.get("href", "")
            if href:
                favicon_info["present"] = True
                favicon_info["href"] = truncate(href, 500)
                abs_href = urljoin(page_url, href)
                fav_host = hostname_from_url(abs_href)
                if fav_host:
                    fav_parts = parse_host(fav_host)
                    favicon_info["domain"] = truncate(fav_parts.registered_domain or fav_host, 200)
                    if fav_parts.registered_domain and fav_parts.registered_domain != page_registered:
                        favicon_info["external"] = True
            break  # Use first found favicon

    # --- Forms ------------------------------------------------------------- #
    forms = soup.find_all("form")
    form_count = len(forms)
    with_password = 0
    external_action_count = 0
    action_domains: list[str] = []
    insecure_action = False
    empty_or_js_action = 0
    mailto_action = 0
    hidden_input_count = 0
    login_form = False
    payment_form = False

    for form in forms:
        inputs = form.find_all("input")
        has_pw = any(
            (inp.get("type", "").lower() == "password")
            for inp in inputs
        )
        if has_pw:
            with_password += 1

        hidden_input_count += sum(
            1 for inp in inputs if inp.get("type", "").lower() == "hidden"
        )

        action = (form.get("action") or "").strip()
        if not action or action.startswith("javascript:") or action == "#":
            empty_or_js_action += 1
        elif action.lower().startswith("mailto:"):
            mailto_action += 1
        else:
            abs_action = urljoin(page_url, action)
            if _is_external(abs_action, page_host, page_registered):
                external_action_count += 1
                act_host = hostname_from_url(abs_action)
                act_parts = parse_host(act_host)
                act_domain = act_parts.registered_domain or act_host
                if act_domain and act_domain not in action_domains:
                    action_domains.append(truncate(act_domain, 200))
            parsed_action = urlsplit(abs_action)
            if parsed_action.scheme == "http" and has_pw:
                insecure_action = True

        # Detect login / payment forms by input characteristics
        form_text = form.get_text(separator=" ", strip=True).lower()
        input_types = {inp.get("type", "text").lower() for inp in inputs}
        input_names = {(inp.get("name") or "").lower() for inp in inputs}
        input_placeholders = {(inp.get("placeholder") or "").lower() for inp in inputs}

        all_form_signals = form_text + " " + " ".join(input_names) + " " + " ".join(input_placeholders)

        if has_pw or any(t in all_form_signals for t in ("username", "email", "login", "signin", "password", "user_id", "userid")):
            login_form = True

        if any(t in all_form_signals for t in ("credit card", "card number", "cvv", "expiry", "billing", "payment", "card_number", "cardnumber", "cc_number")):
            payment_form = True

    action_domains = action_domains[:15]

    # --- Links ------------------------------------------------------------- #
    all_links = soup.find_all("a", href=True)
    link_total = len(all_links) + len(soup.find_all("a", href=False))
    null_fragment_hrefs = soup.find_all("a", href=False)
    link_internal = 0
    link_external = 0
    link_null_or_fragment = len(null_fragment_hrefs)  # <a> without href
    external_link_domains: list[str] = []

    for a_tag in all_links:
        href = a_tag.get("href", "")
        if _is_null_or_fragment(href):
            link_null_or_fragment += 1
        else:
            abs_href = urljoin(page_url, href)
            if _is_external(abs_href, page_host, page_registered):
                link_external += 1
                ext_host = hostname_from_url(abs_href)
                ext_parts = parse_host(ext_host)
                ext_domain = ext_parts.registered_domain or ext_host
                if ext_domain and ext_domain not in external_link_domains:
                    external_link_domains.append(truncate(ext_domain, 200))
            else:
                link_internal += 1

    external_link_domains = external_link_domains[:15]
    link_total_nonzero = max(link_total, 1)
    external_ratio = round(link_external / link_total_nonzero, 4) if link_total > 0 else 0.0
    null_ratio = round(link_null_or_fragment / link_total_nonzero, 4) if link_total > 0 else 0.0

    # --- Resources (scripts, stylesheets, images) -------------------------- #
    script_tags = soup.find_all("script", src=True)
    stylesheet_tags = soup.find_all("link", rel=lambda v: v and "stylesheet" in [x.lower() for x in v])
    img_tags = soup.find_all("img", src=True)

    total_scripts = len(script_tags) + len(soup.find_all("script"))  # src + inline
    external_scripts = 0
    total_stylesheets = len(stylesheet_tags)
    total_images = len(img_tags)
    resource_external_domains: list[str] = []
    external_resource_count = 0

    for script_tag in script_tags:
        src = script_tag.get("src", "")
        abs_src = urljoin(page_url, src)
        if _is_external(abs_src, page_host, page_registered):
            external_scripts += 1
            external_resource_count += 1
            rhost = hostname_from_url(abs_src)
            rparts = parse_host(rhost)
            rd = rparts.registered_domain or rhost
            if rd and rd not in resource_external_domains:
                resource_external_domains.append(truncate(rd, 200))

    for ss_tag in stylesheet_tags:
        href = ss_tag.get("href", "")
        if href:
            abs_href = urljoin(page_url, href)
            if _is_external(abs_href, page_host, page_registered):
                external_resource_count += 1
                rhost = hostname_from_url(abs_href)
                rparts = parse_host(rhost)
                rd = rparts.registered_domain or rhost
                if rd and rd not in resource_external_domains:
                    resource_external_domains.append(truncate(rd, 200))

    for img_tag in img_tags:
        src = img_tag.get("src", "")
        abs_src = urljoin(page_url, src)
        if _is_external(abs_src, page_host, page_registered):
            external_resource_count += 1
            rhost = hostname_from_url(abs_src)
            rparts = parse_host(rhost)
            rd = rparts.registered_domain or rhost
            if rd and rd not in resource_external_domains:
                resource_external_domains.append(truncate(rd, 200))

    resource_external_domains = resource_external_domains[:15]
    total_resources = len(script_tags) + total_stylesheets + total_images
    external_resource_ratio = round(external_resource_count / max(total_resources, 1), 4) if total_resources > 0 else 0.0

    # --- Iframes ----------------------------------------------------------- #
    iframes = soup.find_all("iframe")
    iframe_count = len(iframes)
    iframe_hidden = 0
    iframe_external = 0

    for iframe in iframes:
        style = (iframe.get("style") or "").lower()
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        if ("display:none" in style.replace(" ", "") or
                "visibility:hidden" in style.replace(" ", "") or
                "opacity:0" in style.replace(" ", "") or
                width in ("0", "1") or height in ("0", "1")):
            iframe_hidden += 1
        src = iframe.get("src", "")
        if src:
            abs_src = urljoin(page_url, src)
            if _is_external(abs_src, page_host, page_registered):
                iframe_external += 1

    # --- Hidden elements --------------------------------------------------- #
    hidden_elements = 0
    for tag in soup.find_all(style=True):
        style_val = tag.get("style", "").lower().replace(" ", "")
        if "display:none" in style_val or "visibility:hidden" in style_val:
            hidden_elements += 1
    for tag in soup.find_all(attrs={"hidden": True}):
        hidden_elements += 1

    # --- Inline scripts & suspicious patterns ------------------------------ #
    inline_scripts = soup.find_all("script")
    inline_count = sum(1 for s in inline_scripts if not s.get("src"))
    suspicious_patterns: list[dict] = []

    all_inline_js = " ".join(
        s.string or "" for s in inline_scripts if not s.get("src") and s.string
    )
    for pat_info in _SUSPICIOUS_JS_PATTERNS:
        count = len(re.findall(pat_info["pattern"], all_inline_js))
        if count > 0:
            suspicious_patterns.append({
                "pattern": pat_info["pattern"],
                "count": count,
                "description": pat_info["description"],
            })

    # --- Keywords ---------------------------------------------------------- #
    text_lower = visible_text.lower()
    title_lower = (title or "").lower()
    combined_text = text_lower + " " + title_lower

    found_login_terms = sorted({
        term for term in _LOGIN_TERMS if term in combined_text
    })
    found_urgency_terms = sorted({
        term for term in _URGENCY_TERMS if term in combined_text
    })
    found_payment_terms = sorted({
        term for term in _PAYMENT_TERMS if term in combined_text
    })

    has_password_field = with_password > 0
    has_login_wording = len(found_login_terms) > 0

    # --- Meta refresh & JS redirect ---------------------------------------- #
    meta_refresh = _extract_meta_refresh(soup)
    js_redirect = _detect_js_redirect(soup)

    # --- Mixed content ----------------------------------------------------- #
    page_scheme = urlsplit(page_url).scheme
    mixed_content_examples: list[str] = []
    mixed_content_count = 0

    if page_scheme == "https":
        for tag_name, attr_name in [("script", "src"), ("link", "href"), ("img", "src"),
                                     ("iframe", "src"), ("object", "data"), ("embed", "src")]:
            for tag in soup.find_all(tag_name, **{attr_name: True}):
                val = tag.get(attr_name, "")
                abs_val = urljoin(page_url, val)
                if abs_val.startswith("http://"):
                    mixed_content_count += 1
                    if len(mixed_content_examples) < 5:
                        mixed_content_examples.append(truncate(abs_val, 200))

    # --- Copyright text ---------------------------------------------------- #
    copyright_text = None
    for text_node in soup.find_all(string=re.compile(r"(?:©|copyright|©)", re.IGNORECASE)):
        parent = text_node.parent
        if parent and parent.name not in ("script", "style"):
            copyright_text = truncate(text_node.strip(), 200)
            break

    # --- Structure anomalies ----------------------------------------------- #
    has_html_tag = soup.find("html") is not None
    has_head = soup.find("head") is not None
    has_body = soup.find("body") is not None
    has_title = title_tag is not None
    text_length = len(visible_text)
    element_count = len(soup.find_all(True))

    anomalies: list[str] = []
    if not has_html_tag:
        anomalies.append("Missing <html> tag")
    if not has_head:
        anomalies.append("Missing <head> tag")
    if not has_body:
        anomalies.append("Missing <body> tag")
    if not has_title:
        anomalies.append("Missing <title> tag")
    if text_length < 50 and element_count > 5:
        anomalies.append("Very short visible text relative to element count")
    if element_count < 5 and bytes_analyzed > 500:
        anomalies.append("Very few HTML elements for page size")

    # --- Brand text mentions ----------------------------------------------- #
    brand_text_mentions: list[str] = []
    search_text = combined_text.replace("-", "").replace(".", "")
    for brand in BRAND_OFFICIAL_DOMAINS:
        if len(brand) >= 3 and brand in search_text:
            brand_text_mentions.append(brand)

    # --- Findings ---------------------------------------------------------- #
    _source = "webpage_analyzer"

    if has_password_field:
        findings.append(make_finding(
            "webpage.password_field", "medium", "webpage",
            "Page contains a password input field.",
            points=12, source=_source,
        ))

    if login_form and has_password_field:
        findings.append(make_finding(
            "webpage.login_form", "info", "webpage",
            "Page contains a login form with password field.",
            source=_source,
        ))

    if payment_form:
        findings.append(make_finding(
            "webpage.payment_form", "medium", "webpage",
            "Page contains a payment or financial data form.",
            points=14, source=_source,
        ))

    if external_action_count > 0:
        findings.append(make_finding(
            "webpage.form_external_action", "medium", "webpage",
            f"Form submits data to an external domain ({external_action_count} form(s)).",
            detail=truncate(", ".join(action_domains), 300),
            points=15, source=_source,
        ))

    if insecure_action:
        findings.append(make_finding(
            "webpage.form_insecure_action", "strong", "webpage",
            "Password form submits credentials over insecure HTTP.",
            points=25, source=_source,
        ))

    if empty_or_js_action > 0:
        findings.append(make_finding(
            "webpage.form_empty_action", "low", "webpage",
            f"Form has empty or JavaScript action ({empty_or_js_action} form(s)).",
            points=4, source=_source,
        ))

    if null_ratio > 0.7 and link_total > 5:
        findings.append(make_finding(
            "webpage.high_null_link_ratio", "low", "webpage",
            f"High proportion of null/fragment links ({null_ratio:.0%}).",
            points=5, source=_source,
        ))

    if external_ratio > 0.8 and link_total > 3:
        findings.append(make_finding(
            "webpage.high_external_link_ratio", "low", "webpage",
            f"Most links point to external domains ({external_ratio:.0%}).",
            points=4, source=_source,
        ))

    if iframe_hidden > 0:
        findings.append(make_finding(
            "webpage.hidden_iframe", "medium", "webpage",
            f"Page contains {iframe_hidden} hidden iframe(s).",
            points=14, source=_source,
        ))

    if iframe_external > 0:
        findings.append(make_finding(
            "webpage.external_iframe", "low", "webpage",
            f"Page loads {iframe_external} iframe(s) from external domains.",
            points=5, source=_source,
        ))

    if hidden_elements > 10:
        findings.append(make_finding(
            "webpage.many_hidden_elements", "low", "webpage",
            f"Page contains {hidden_elements} hidden elements.",
            points=4, source=_source,
        ))

    if len(suspicious_patterns) > 0:
        desc_list = [p["description"] for p in suspicious_patterns[:5]]
        findings.append(make_finding(
            "webpage.suspicious_scripts", "medium", "webpage",
            f"Inline scripts contain suspicious patterns: {', '.join(desc_list)}.",
            points=12, source=_source,
        ))

    if found_urgency_terms:
        findings.append(make_finding(
            "webpage.urgency_language", "low", "webpage",
            f"Page uses urgency language: {truncate(', '.join(found_urgency_terms[:5]), 200)}.",
            points=5, source=_source,
        ))

    if found_payment_terms and not payment_form:
        findings.append(make_finding(
            "webpage.payment_keywords", "low", "webpage",
            f"Page mentions payment/financial terms: {truncate(', '.join(found_payment_terms[:5]), 200)}.",
            points=4, source=_source,
        ))

    if meta_refresh is not None and meta_refresh.get("url"):
        findings.append(make_finding(
            "webpage.meta_refresh", "medium", "webpage",
            "Page uses meta http-equiv refresh to redirect.",
            detail=truncate(f"Delay: {meta_refresh['delay']}s, URL: {meta_refresh['url']}", 300),
            points=12, source=_source,
        ))

    if js_redirect:
        findings.append(make_finding(
            "webpage.js_redirect", "low", "webpage",
            "Inline JavaScript sets window.location (potential redirect).",
            points=6, source=_source,
        ))

    if mixed_content_count > 0:
        findings.append(make_finding(
            "webpage.mixed_content", "low", "webpage",
            f"HTTPS page loads {mixed_content_count} resource(s) over HTTP.",
            points=5, source=_source,
        ))

    if anomalies:
        findings.append(make_finding(
            "webpage.structure_anomaly", "low", "webpage",
            f"Page structure anomalies detected: {truncate(', '.join(anomalies), 200)}.",
            points=4, source=_source,
        ))

    if inline_count > 10:
        findings.append(make_finding(
            "webpage.many_inline_scripts", "low", "webpage",
            f"Page contains {inline_count} inline scripts.",
            points=3, source=_source,
        ))

    # --- Assemble result --------------------------------------------------- #
    return {
        "status": "ok",
        "message": None,
        "http_status": http_status,
        "content_type": truncate(content_type_raw, 100),
        "bytes_analyzed": bytes_analyzed,
        "truncated": fetch.truncated,
        "title": title,
        "meta_description": meta_description,
        "language": language,
        "favicon": favicon_info,
        "forms": {
            "count": form_count,
            "with_password": with_password,
            "external_action_count": external_action_count,
            "action_domains": action_domains,
            "insecure_action": insecure_action,
            "empty_or_js_action": empty_or_js_action,
            "mailto_action": mailto_action,
            "hidden_input_count": hidden_input_count,
            "login_form": login_form,
            "payment_form": payment_form,
        },
        "links": {
            "total": link_total,
            "internal": link_internal,
            "external": link_external,
            "null_or_fragment": link_null_or_fragment,
            "external_ratio": external_ratio,
            "null_ratio": null_ratio,
            "external_domains": external_link_domains,
        },
        "resources": {
            "scripts": total_scripts,
            "external_scripts": external_scripts,
            "stylesheets": total_stylesheets,
            "images": total_images,
            "external_resource_ratio": external_resource_ratio,
            "external_domains": resource_external_domains,
        },
        "iframes": {
            "count": iframe_count,
            "hidden": iframe_hidden,
            "external": iframe_external,
        },
        "hidden_elements": hidden_elements,
        "scripts": {
            "inline_count": inline_count,
            "suspicious_patterns": suspicious_patterns,
        },
        "keywords": {
            "login_terms": found_login_terms,
            "urgency_terms": found_urgency_terms,
            "payment_terms": found_payment_terms,
        },
        "has_password_field": has_password_field,
        "has_login_wording": has_login_wording,
        "meta_refresh": meta_refresh,
        "js_redirect": js_redirect,
        "mixed_content": {
            "detected": mixed_content_count > 0,
            "count": mixed_content_count,
            "examples": mixed_content_examples,
        },
        "copyright_text": copyright_text,
        "structure": {
            "has_html_tag": has_html_tag,
            "has_head": has_head,
            "has_body": has_body,
            "has_title": has_title,
            "text_length": text_length,
            "element_count": element_count,
            "anomalies": anomalies,
        },
        "brand_text_mentions": brand_text_mentions,
        "findings": findings,
    }


def _empty_result(
    *,
    status: str,
    message: str,
    http_status: int | None = None,
    content_type: str | None = None,
    bytes_analyzed: int = 0,
    truncated: bool = False,
    findings: list[dict] | None = None,
) -> dict:
    """Return the full contract shape with empty / default values."""
    return {
        "status": status,
        "message": message,
        "http_status": http_status,
        "content_type": content_type,
        "bytes_analyzed": bytes_analyzed,
        "truncated": truncated,
        "title": None,
        "meta_description": None,
        "language": None,
        "favicon": {"present": False, "href": None, "external": False, "domain": None},
        "forms": {
            "count": 0, "with_password": 0, "external_action_count": 0,
            "action_domains": [], "insecure_action": False, "empty_or_js_action": 0,
            "mailto_action": 0, "hidden_input_count": 0, "login_form": False,
            "payment_form": False,
        },
        "links": {
            "total": 0, "internal": 0, "external": 0, "null_or_fragment": 0,
            "external_ratio": 0.0, "null_ratio": 0.0, "external_domains": [],
        },
        "resources": {
            "scripts": 0, "external_scripts": 0, "stylesheets": 0, "images": 0,
            "external_resource_ratio": 0.0, "external_domains": [],
        },
        "iframes": {"count": 0, "hidden": 0, "external": 0},
        "hidden_elements": 0,
        "scripts": {"inline_count": 0, "suspicious_patterns": []},
        "keywords": {"login_terms": [], "urgency_terms": [], "payment_terms": []},
        "has_password_field": False,
        "has_login_wording": False,
        "meta_refresh": None,
        "js_redirect": False,
        "mixed_content": {"detected": False, "count": 0, "examples": []},
        "copyright_text": None,
        "structure": {
            "has_html_tag": False, "has_head": False, "has_body": False, "has_title": False,
            "text_length": 0, "element_count": 0, "anomalies": [],
        },
        "brand_text_mentions": [],
        "findings": findings if findings is not None else [],
    }
