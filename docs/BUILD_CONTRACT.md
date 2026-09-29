# PhishGuard - Build Contract (internal interface specification)

This document is the single source of truth for module boundaries, function
signatures, data shapes and API routes. Every module MUST conform to it so that
independently written parts integrate without changes. If you must deviate,
keep backwards-compatible (add fields, never rename/remove).

Project root: `phishguard/` (all commands run from here).
Python 3.14, packages available: fastapi 0.115, uvicorn, httpx 0.28, httpcore,
beautifulsoup4 4.12 (use the built-in `html.parser`, lxml is NOT installed),
scikit-learn 1.9, xgboost 3.4, numpy 2.4, joblib, sqlalchemy 2.1, bcrypt 5,
pyjwt 2.15, reportlab 5, dnspython 2.8, python-whois 0.9, tldextract 5.3,
cryptography 50, certifi, idna, pytest 9, python-multipart, email-validator,
python-dotenv, pydantic 2.12. pandas is NOT installed (use csv/numpy).

Imports are absolute from the project root: `from backend.config import settings`,
`from backend.services.common import make_finding`, `from ml.feature_extractor import ...`.
Run the app: `python -m uvicorn backend.main:app --reload` (serves API + frontend).
Run tests: `python -m pytest -q` from `phishguard/`.

Already written (do NOT rewrite; you may read them):
* `backend/config.py` - `settings` singleton + path constants (BASE_DIR, FRONTEND_DIR, ML_DIR, REPORTS_DIR, DATA_DIR).
* `backend/services/common.py` - `make_finding(...)`, `truncate(...)`, severities/categories.
* `ml/feature_extractor.py` - `parse_host`, `HostParts`, `extract_ml_features`, `ML_FEATURE_NAMES`,
  `features_to_vector`, `BRAND_OFFICIAL_DOMAINS`, `SUSPICIOUS_TLDS`, `SUSPICIOUS_HOST_KEYWORDS`,
  `SHARED_HOSTING_DOMAINS`, `brands_outside_official_domain`, `is_shared_hosting_subdomain`, `is_ip_literal`.
* `ml/dataset/phiusiil.zip` - PhiUSIIL Phishing URL Dataset (UCI id 967), 235,795 rows, label 1 = legitimate, 0 = phishing.
* `frontend/vendor/chart.umd.min.js` - Chart.js 4.4.7 (local copy, no CDN).

## 0. Non-negotiable principles

1. **Defensive only.** Never submit forms, never send credentials, never
   persist or return cookies / Set-Cookie values / session tokens, never try
   to bypass auth, CAPTCHA, WAF, or bot challenges (403/429/503 challenge pages are
   reported as "access restricted", not circumvented).
2. **Never fabricate.** If a value cannot be obtained, use `None` in data and
   the string `"Unavailable"` (or an explicit message) in human text. Never
   guess domain ages, registrars, ASNs, metrics, etc.
3. **No single-feature verdicts.** A single finding can never push the final
   classification to PHISHING by itself; only combinations can (see risk engine).
4. **HTTPS is not trust.** A valid certificate may reduce risk slightly only.
5. **Untrusted text.** Page titles, descriptions, URLs, form actions, etc. are
   attacker-controlled. Backend: truncate with `truncate()`; never store raw HTML.
   Frontend: insert ONLY via `textContent`/`setAttribute` (never `innerHTML` with
   data). PDF: escape for reportlab (`xml.sax.saxutils.escape`).
6. **SSRF safety.** Every outbound request to a user-controlled destination goes
   through `backend/security/ssrf_protection.py` (validated + IP-pinned). Fixed,
   well-known third-party services (rdap.org + registry RDAP servers, Google Safe
   Browsing, Team Cymru DNS) may use plain httpx/dnspython with timeouts,
   `trust_env=False` and response-size limits.

## 1. Findings (shared)

`backend/services/common.py::make_finding(id, severity, category, message, *, detail=None, points=None, source="")`
returns `{"id","severity","category","message","detail","points","source"}`.
Severity: `strong|medium|low|positive|info`. Category: `url|redirect|domain|tls|webpage|brand|reputation|ml|rule`.
Points: + raises risk, - lowers. Guideline: strong 20..35, medium 10..18, low 3..8, positive -3..-15, info 0.
Finding ids are dotted & stable, e.g. `url.ip_host`, `tls.cert_expired`, `rule.brand_credential_mismatch`.

## 2. Security layer - `backend/security/`

### 2.1 `validation.py`

```python
class URLValidationError(Exception):
    code: str      # INVALID_URL | UNSUPPORTED_PROTOCOL | URL_TOO_LONG | BLOCKED_HOST | BLOCKED_PORT | PRIVATE_ADDRESS
    message: str   # user-safe message
    def __init__(self, code: str, message: str): ...

@dataclass(frozen=True)
class NormalizedURL:
    original: str          # raw input (stripped)
    normalized: str        # canonical URL WITHOUT userinfo, idna host, default port removed, path at least "/"
    scheme: str            # "http" | "https"
    hostname: str          # lower-case idna/punycode (IPv6 without brackets)
    port: int | None       # explicit port if given, else None
    effective_port: int    # port actually used (80/443 default)
    path: str
    query: str
    fragment: str
    had_userinfo: bool     # input contained user[:pass]@ (stripped, never sent)
    scheme_assumed: bool   # input had no scheme -> "https://" assumed
    is_ip: bool

def normalize_url(raw: str) -> NormalizedURL   # raises URLValidationError
def check_host_allowed(hostname: str) -> None  # static hostname policy (no DNS). raises URLValidationError(BLOCKED_HOST|PRIVATE_ADDRESS)
def redact_url(url: str) -> str
    # Privacy: returns the URL with userinfo removed and the VALUES of sensitive-looking query/fragment
    # parameters replaced by "REDACTED" (names containing: token, auth, session, sid, key, secret, password,
    # passwd, pwd, pass, otp, code, sig, signature, jwt, credential, ticket, nonce, email). Used for EVERY URL
    # that is stored in the database or returned in a report (url, normalized_url, final_url, redirect chain).
    # Fetching still uses the real URL.
```

Rules: strip whitespace; reject empty, control chars, spaces inside host, > `settings.MAX_URL_LENGTH` (URL_TOO_LONG).
Accept `http`/`https` only (case-insensitive) -> anything else (`file:`, `ftp:`, `javascript:`, `data:`,
`gopher:`, `ws:`, `mailto:`, `vbscript:`, `blob:` ...) = UNSUPPORTED_PROTOCOL. No scheme and host-like input ->
prepend `https://` and set `scheme_assumed=True`. Port must be in `settings.ALLOWED_PORTS` (else BLOCKED_PORT).
IDNA-encode unicode hostnames. Static host policy: `localhost`, `*.localhost`, `*.local`, `*.internal`,
`*.intranet`, `*.lan`, `*.home`, `*.corp`, `*.home.arpa`, `*.localdomain`, `metadata.google.internal`,
`metadata`, `instance-data`, single-label hostnames (no dot, non-IP) and `settings.BLOCKED_HOSTNAMES` -> BLOCKED_HOST.
IP literals (incl. obfuscated forms: decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, short `127.1`,
IPv4-mapped IPv6 `::ffff:127.0.0.1`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16` embedding) must be canonicalised and
checked with `is_ip_allowed` -> PRIVATE_ADDRESS.

### 2.2 `ssrf_protection.py`

```python
class BlockedDestinationError(Exception): code = "BLOCKED_DESTINATION"; message: str
class FetchError(Exception):
    code: str      # TIMEOUT | DNS_FAILURE | CONNECTION_FAILED | SSL_ERROR | TOO_MANY_REDIRECTS |
                   # BLOCKED_DESTINATION | UNSUPPORTED_PROTOCOL | INVALID_URL | RESPONSE_TOO_LARGE | HTTP_ERROR
    message: str
    redirect_chain: list["RedirectHop"]   # hops completed before the failure

def is_ip_allowed(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool
    # False for: loopback, private (RFC1918, fc00::/7), link-local (169.254/16, fe80::/10), CGNAT 100.64/10,
    # unspecified, multicast, reserved, broadcast, 0.0.0.0/8, benchmarking 198.18/15, documentation ranges,
    # site-local fec0::/10, IPv4-mapped/compat/6to4/NAT64/Teredo addresses embedding a disallowed IPv4,
    # metadata 169.254.169.254 / fd00:ec2::254, and anything where `ip.is_global` is False.

def resolve_and_validate(hostname: str, port: int) -> list[str]
    # getaddrinfo (TCP) -> list of IP strings; raises FetchError(DNS_FAILURE) when unresolvable,
    # BlockedDestinationError if ANY resolved address is disallowed (fail closed) or host policy blocks it.

@dataclass
class RedirectHop:
    url: str; status_code: int; location: str | None; ip: str | None

@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]        # lower-case names; Set-Cookie / Cookie REMOVED
    content: bytes                 # at most max_bytes
    truncated: bool                # True if body exceeded max_bytes (content is the first max_bytes)
    content_type: str              # e.g. "text/html"
    encoding: str | None           # charset from header or None
    redirect_chain: list[RedirectHop]   # every 3xx hop in order (empty if none)
    ip: str | None                 # IP actually connected to for the final response
    elapsed_ms: int
    tls_verified: bool             # True if final hop was https with verification on

def safe_fetch(url: str, *, method: str = "GET", max_bytes: int | None = None,
               follow_redirects: bool = True, max_redirects: int | None = None,
               verify_tls: bool = True, timeout: float | None = None) -> FetchResult
```

Implementation requirements: httpx with `trust_env=False`, no proxies, fresh client per call (no cookie
persistence), `follow_redirects=False` + manual redirect loop (each Location resolved against current URL,
re-validated with `normalize_url` + `resolve_and_validate`), max redirects -> TOO_MANY_REDIRECTS.
**DNS-rebinding-safe IP pinning**: the TCP connection must go to the exact IP that was validated. Implement
a custom `httpcore` network backend (subclass of `httpcore.SyncBackend` overriding `connect_tcp`) that resolves +
validates the host at connect time and connects to the validated IP, while TLS SNI/certificate verification still
uses the hostname (httpcore passes `server_hostname`). Install it on the transport's pool
(`transport._pool._network_backend = PinnedBackend()` is acceptable; document it). Stream the body and stop at
`max_bytes` (default `settings.FETCH_MAX_BYTES`), setting `truncated=True` (not an error). Reject
`Content-Length` > 10x max_bytes early with RESPONSE_TOO_LARGE. Enforce a total wall-clock budget
(`settings.FETCH_TOTAL_TIMEOUT`) across all hops -> TIMEOUT. Map httpx exceptions: ConnectTimeout/ReadTimeout/
PoolTimeout -> TIMEOUT, ConnectError with SSL cause -> SSL_ERROR, other ConnectError -> CONNECTION_FAILED,
socket.gaierror -> DNS_FAILURE. Send `User-Agent: settings.FETCH_USER_AGENT`, `Accept: text/html,*/*;q=0.8`.
No cookies/credentials/auth headers are ever sent. HTTP >= 400 is NOT an exception (returned in `status_code`).

Also provide `probe_http_to_https(hostname: str, port: int | None = None) -> bool | None`:
GET `http://host/` with `follow_redirects=False`, max_bytes 16KB -> True if response is 3xx to an `https://` URL
on any host, False if it serves content over HTTP, None if unreachable/blocked.

### 2.3 `rate_limiter.py`

```python
class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0): ...
    def hit(self, key: str) -> tuple[bool, int]   # (allowed, retry_after_seconds); thread-safe; bounded memory
    def reset(self) -> None
class ConcurrencyLimiter:
    def __init__(self, max_concurrent: int): ...
    def try_acquire(self) -> bool; def release(self) -> None
    # context-manager helper: `with limiter.slot() as ok:`
scan_ip_limiter, scan_session_limiter, auth_ip_limiter, scan_concurrency   # module-level singletons from settings
def client_ip(request) -> str   # honours X-Forwarded-For only if settings.TRUST_PROXY_HEADERS
```

## 3. Analyzers - `backend/services/`

All analyzers are synchronous, never raise for expected network problems (they return
`status: "unavailable"|"error"` with a message) and always include `"findings": [...]`.

### 3.1 `url_analyzer.py`
`analyze_url(nurl: NormalizedURL) -> dict`:
```
status:"ok", scheme, https(bool), scheme_assumed, hostname, hostname_unicode (decoded IDN for display),
registered_domain, subdomain, tld, port, url_length, hostname_length, domain_length, path, path_length,
path_depth, num_dots, num_subdomains, num_hyphens, num_digits, num_special_chars, num_query_params,
num_path_params, has_at_symbol, has_ip, ip_version (4|6|None), has_punycode, has_suspicious_encoding,
percent_encoded_count, has_double_slash_redirect, has_fragment, has_non_standard_port, suspicious_tld(bool),
suspicious_keywords(list[str]), suspicious_keyword_count, is_shortener(bool), shortener_service(str|None),
random_domain_score(0..1 float), hex_char_ratio, has_long_hex_sequence, domain_entropy, brand_tokens(list),
brands_outside_official(list), shared_hosting(bool), ml_features(dict from extract_ml_features), findings[]
```
Note: `has_at_symbol` and credentials must be computed from `nurl.original` (userinfo is stripped from
`normalized`). Suppress the "no HTTPS" finding when `scheme_assumed` is True.

### 3.2 `redirect_analyzer.py`
`analyze_redirects(requested: NormalizedURL, fetch: FetchResult | None, *, http_probe: bool | None, page_signals: dict | None) -> dict`:
```
status:"ok"|"unavailable", num_redirects, chain:[{url,status_code,host,registered_domain,cross_domain}],
final_url, final_host, final_registered_domain, crossed_domains(bool), distinct_domains(int),
https_downgrade(bool), upgraded_to_https(bool), http_redirects_to_https(bool|None),
meta_refresh(dict|None {url, delay}), js_redirect_detected(bool), shortener_expanded(bool), findings[]
```
`page_signals` = `webpage_analysis` dict (for meta refresh / JS redirect), may be None.

### 3.3 `tls_analyzer.py`
`analyze_tls(hostname: str, port: int = 443, *, https_requested: bool = True) -> dict`:
Connects to a `resolve_and_validate`d IP with `ssl` (SNI=hostname), verifying against certifi's CA bundle; on
verification failure reconnects with CERT_NONE to read the certificate (parse DER with `cryptography`) for display.
```
status:"ok"|"unavailable"|"error", https_available(bool|None), certificate_valid(bool|None),
validation_error(str|None), hostname_match(bool|None), issuer{common_name,organization},
subject{common_name,organization}, san(list[str] max 25), not_before(iso|None), not_after(iso|None),
days_until_expiry(int|None), certificate_age_days(int|None), tls_version(str|None), cipher(str|None),
self_signed(bool|None), issuer_category("free_dv"|"commercial"|"unknown"),
mixed_content(filled later by pipeline: {detected,count,examples}), 
note:"HTTPS protects the connection but does not guarantee that the website itself is trustworthy.", findings[]
```
Timeouts: settings.FETCH_CONNECT_TIMEOUT. Never sends application data beyond the TLS handshake.

### 3.4 `webpage_analyzer.py`
`analyze_webpage(fetch: FetchResult | None, *, page_url: str, fetch_error: FetchError | None = None) -> dict`:
Parses HTML with BeautifulSoup(`html.parser`). Only analyzes text/html or application/xhtml+xml content.
```
status:"ok"|"unavailable"|"restricted"|"error", message(str|None), http_status, content_type,
bytes_analyzed, truncated, title, meta_description, language,
favicon{present, href, external, domain}, 
forms{count, with_password, external_action_count, action_domains[], insecure_action(bool),
      empty_or_js_action(int), mailto_action(int), hidden_input_count, login_form(bool), payment_form(bool)},
links{total, internal, external, null_or_fragment, external_ratio, null_ratio, external_domains[] (<=15)},
resources{scripts, external_scripts, stylesheets, images, external_resource_ratio, external_domains[] (<=15)},
iframes{count, hidden, external},
hidden_elements(int),
scripts{inline_count, suspicious_patterns:[{pattern, count, description}]},
keywords{login_terms[], urgency_terms[], payment_terms[]},
has_password_field(bool), has_login_wording(bool), meta_refresh({url, delay}|None), js_redirect(bool),
mixed_content{detected, count, examples[] (<=5)}, copyright_text(str|None),
structure{has_html_tag, has_head, has_body, has_title, text_length, element_count, anomalies[]},
brand_text_mentions(list[str]),   # brand names from ml.feature_extractor.BRAND_OFFICIAL_DOMAINS found in title/visible text
findings[]
```
`restricted` = HTTP 401/403/407/429/451/503 or bot-challenge page detected ("Access restricted - PhishGuard does not
bypass access controls."). All text fields truncated. Never store/return raw HTML or form values.

### 3.5 `brand_detector.py`
`analyze_brand(url_analysis: dict, webpage_analysis: dict | None, final_registered_domain: str | None) -> dict`:
```
status:"ok", brands_detected:[{brand, display_name, sources[] ("hostname"|"title"|"text"|"favicon"|"form_action"|"copyright"),
official_domains[], domain_matches_official(bool)}],
impersonation_suspected(bool), typosquat{detected(bool), brand, official_domain, similarity(0..1),
technique("homoglyph"|"edit_distance"|"combosquat"|"punycode"|None)}, explanation(str|None), findings[]
```
Brand in title/text alone on a non-official domain is at most `low`; escalation requires combination with
credential/payment wording or forms (the rule engine handles strong escalation).

### 3.6 `domain_analyzer.py`
`analyze_domain(hostname: str, *, resolved_ips: list[str] | None = None) -> dict`:
```
status:"ok"|"partial"|"unavailable", domain(registered domain), hostname, tld,
registration{available(bool), source("rdap"|"whois"|None), created(iso|None), updated, expires,
  domain_age_days(int|None), days_until_expiry(int|None), registrar(str|None), statuses[],
  message("Domain registration information unavailable." when not available)},
dns{resolves(bool), a[], aaaa[], mx[], ns[], cname(str|None), has_spf(bool|None), has_dmarc(bool|None), error(str|None)},
ip_address(str|None), 
asn{asn, prefix, country, registry, as_name} | None,
popularity{available(bool), rank(int|None), source("Tranco top-N"), message},
reputation{configured(bool), provider(str|None), listed(bool|None), threats[], message},
shared_hosting(bool), findings[]
```
RDAP: GET `settings.RDAP_BOOTSTRAP_URL + domain` (follow redirects to registry, max 5, 6s, <=1MB, trust_env=False);
parse `events` (registration/last changed/expiration), registrar entity vcard `fn`, `status`. Fallback
`python-whois` if `settings.ENABLE_WHOIS_FALLBACK`. ASN: Team Cymru DNS (`<rev-ip>.origin.asn.cymru.com` TXT and
`AS<n>.asn.cymru.com` TXT) if `settings.ENABLE_ASN_LOOKUP`. Popularity: Tranco CSV at `settings.TRANCO_LIST_PATH`
if it exists (load once, top `settings.TRANCO_TOP_N`), else available=False, message "Popularity list not installed".
Reputation: Google Safe Browsing v4 `threatMatches:find` only if `settings.GOOGLE_SAFE_BROWSING_API_KEY`, else
configured=False, message "No reputation API configured". Everything unavailable -> None + message; NEVER invent.
Cache results in-process for 1 hour (LRU) to be polite to RDAP.

### 3.7 `ml_detector.py`
```python
def get_model_info() -> dict   # contents of metrics.json summary + loaded flag (for /api/model/info, /api/health)
def predict(ml_features: dict) -> dict
```
`predict` returns:
```
status:"ok"|"unavailable", message, model_name, model_version, trained_at, dataset, feature_set:"host-lexical-v1",
probability_phishing(float|None), probability_legitimate(float|None),
ml_verdict("LEGITIMATE"|"SUSPICIOUS"|"PHISHING"|None),  # by settings.ML_SUSPICIOUS_THRESHOLD / ML_PHISHING_THRESHOLD
thresholds{suspicious, phishing}, top_features:[{feature, value, importance}] (top 6 by global importance * presence),
features(dict), note: "The model is binary (legitimate vs phishing). SUSPICIOUS is a probability band, not a learned class.",
findings[]   # e.g. ml.high_probability (category "ml"); points NOT used by risk engine for ML (it uses the probability)
```
Model artifact `ml/model.pkl` (joblib) = dict `{"model": sklearn Pipeline/estimator, "feature_names": ML_FEATURE_NAMES,
"model_name", "model_version", "trained_at", "dataset", "sklearn_version", "metrics_summary"}`. Load lazily once
(thread-safe). If missing/incompatible -> status "unavailable" (never crash, never fake).

## 4. Engines - `backend/services/`

### 4.1 `rule_engine.py`
`evaluate_rules(ctx: dict) -> dict` where `ctx` = `{"url": url_analysis, "domain": domain_analysis, "tls": tls_analysis,
"redirect": redirect_analysis, "webpage": webpage_analysis, "brand": brand_analysis, "ml": ml_analysis}` (any may be
None or have status != "ok"). Returns `{"status":"ok", "fired_rules":[{id, name, description, severity, points,
evidence[]}], "findings":[...category "rule"...], "floor": int|None, "floor_reason": str|None}`.
Rules are declared as data (list of Rule objects with id, name, description, severity, points, predicate), so the
methodology page can list them (`list_rules() -> list[dict]`). Must include at least the spec examples:
IP host + suspicious keywords; long URL + multiple redirects + suspicious domain structure; brand impersonation +
domain mismatch; credential form + brand mismatch; password form posting to external/insecure domain; young domain
(<30 days) + login wording; punycode/typosquat + brand; shortener + cross-domain redirect; HTTPS valid (small
reduction only); established domain (>1 year) + popular (Tranco) (reduction); invalid cert + password form; etc.
`floor` implements escalation floors ONLY from multi-signal combinations (e.g. credential form + brand mismatch
=> floor 70). A single rule never sets a floor.

### 4.2 `risk_engine.py`
`compute_risk(ctx: dict, rule_result: dict) -> dict` returns:
```
risk_score(int 0..100), risk_band("Low"|"Moderate"|"High"|"Critical"), classification("LEGITIMATE"|"SUSPICIOUS"|"PHISHING"),
confidence(int 0..100), summary(str), explanation(str), recommendation(str),
components{ml:{score,weight,available,detail}, rules:{...}, webpage:{...}, domain:{...}},
weights_effective{...}, floor_applied(int|None), floor_reason,
category_scores:[{key:"url",label:"URL Security",risk:int|None,status}, {key:"domain",label:"Domain Analysis"},
  {key:"page",label:"Page Structure"}, {key:"redirect",label:"Redirect Analysis"}, {key:"threat",label:"Threat Indicators"}],
indicators:[finding...] (all findings from all analyzers + rules, deduped by id, sorted by severity then |points|),
indicator_groups{strong:[], medium:[], low:[], positive:[], info:[]},
band_thresholds{moderate, high, critical}, method(str short description)
```
Components: ml = probability_phishing*100; rules = saturate(sum points of url+redirect+rule findings);
webpage = saturate(webpage+brand findings); domain = saturate(domain+tls+reputation findings) where
`saturate(p) = 100*(1-exp(-max(p,0)/45))` then minus trust (negative points) with floor 0. Final = weighted mean
over AVAILABLE components with settings.WEIGHT_* renormalised, then `max(final, floor)` if a floor fired, clamp 0..100.
Bands (labelled "Application Risk Classification"): < RISK_BAND_MODERATE Low -> LEGITIMATE; < HIGH Moderate ->
SUSPICIOUS; < CRITICAL High -> PHISHING; else Critical -> PHISHING. Google Safe Browsing listed=True => floor 85.
Confidence (documented formula): data completeness (share of components/analyzers available) combined with agreement
between ML verdict and rule/heuristic verdict and distance of the score from the nearest band boundary; capped
at 98, reduced when webpage unavailable. Explanation text names the top contributing findings ("primarily
influenced by ...").
Also: `classify_score(score:int) -> (band, classification)`.

### 4.3 `analysis_pipeline.py`
```python
STAGES = [("validate","Analyzing URL..."), ("dns","Checking domain..."), ("https","Checking HTTPS..."),
          ("redirects","Following safe redirects..."), ("webpage","Analyzing webpage structure..."),
          ("features","Extracting security features..."), ("model","Running detection model..."),
          ("report","Generating report...")]
def run_analysis(raw_url: str, progress: Callable[[str, str], None] | None = None) -> dict
```
`progress(stage_key, "started"|"done")`. Returns the **report dict** (section 5) WITHOUT `scan_id`/`created_at`
(the API layer adds them after persisting). Raises `URLValidationError` for invalid input (not persisted).
Destination failures return a report with `status="failed"`, `classification="ANALYSIS_FAILED"`,
`risk_score=None`, `confidence=None`, `error={code,message}`:
- BLOCKED_DESTINATION -> "This destination resolves to a restricted network address."
- DNS_FAILURE -> "The domain name could not be resolved." (url_analysis still included)
Partial (webpage not retrievable but host resolves): TIMEOUT -> notice "Website did not respond within the allowed
time.", CONNECTION_FAILED, HTTP errors, restricted pages -> `status="partial"`, still classified (lower confidence).
SSL_ERROR on https: record TLS findings, re-fetch with verify_tls=False to analyze content (never send data).
If scheme_assumed and https connection fails -> retry http://. Domain analysis runs concurrently with fetching
(ThreadPoolExecutor). Total budget `settings.SCAN_TOTAL_TIMEOUT`.
Privacy: before returning, every URL string in the report (`url`, `normalized_url`, `final_url`,
`redirect_analysis.chain[].url`, `redirect_analysis.final_url`, `url_analysis.path`/query-bearing fields) is passed
through `validation.redact_url`. Numeric features are computed on the real URL (lengths may therefore differ
slightly from the displayed redacted URL - acceptable and documented).

## 5. Report JSON (API response of POST /api/analyze and GET /api/report/{id})

```json
{
  "scan_id": "SCAN-2026-00124",
  "url": "<original input>",
  "normalized_url": "https://example.com/",
  "final_url": "https://example.com/",
  "status": "completed | partial | failed",
  "classification": "LEGITIMATE | SUSPICIOUS | PHISHING | ANALYSIS_FAILED",
  "risk_score": 8, "risk_band": "Low", "confidence": 94,
  "summary": "No major phishing indicators were detected from the available public signals.",
  "explanation": "...", "recommendation": "...",
  "created_at": "2026-09-29T10:15:00Z", "duration_ms": 2350,
  "error": null, "notices": [],
  "url_analysis": {}, "domain_analysis": {}, "tls_analysis": {}, "redirect_analysis": {},
  "webpage_analysis": {}, "brand_analysis": {}, "ml_analysis": {}, "rule_analysis": {},
  "scoring": {"components": {}, "weights_effective": {}, "floor_applied": null, "floor_reason": null,
              "band_thresholds": {"moderate":30,"high":60,"critical":80}, "method": "..."},
  "category_scores": [], "indicators": [], "indicator_groups": {},
  "disclaimer": "This automated assessment is based on available technical signals and should not be treated as definitive proof of website legitimacy or maliciousness."
}
```
Sections that could not run are `{"status":"unavailable","message":"...","findings":[]}` - never omitted.

## 6. Persistence - `backend/database.py`, `backend/models.py` (SQLAlchemy 2.x)

`database.py`: `engine`, `SessionLocal`, `Base`, `get_db()` FastAPI dependency, `init_db()` (create_all).
SQLite: `check_same_thread=False`, WAL pragma. DATABASE_URL may be PostgreSQL.

Tables: `users(id, email unique lower, password_hash, role 'user'|'admin', is_active, created_at, last_login_at)`,
`password_reset_tokens(id, user_id FK, token_hash sha256, expires_at, used_at, created_at)`,
`scans(id pk, public_id unique "SCAN-YYYY-NNNNN", user_id FK nullable, anon_session_hash nullable, url, normalized_url,
final_url, hostname, registered_domain, status, classification, risk_score nullable, confidence nullable, risk_band,
error_code, error_message, duration_ms, created_at)`,
`scan_features(scan_id FK unique, url_length, domain_length, num_dots, num_hyphens, num_subdomains, has_ip,
has_at_symbol, has_https, num_redirects, suspicious_keyword_count, external_link_ratio, form_count, iframe_count,
domain_age_days nullable, certificate_valid nullable, punycode_detected, query_parameter_count, path_length,
special_character_count, ml_features_json)`,
`scan_results(scan_id FK unique, summary, report_json TEXT, ml_probability_phishing nullable, model_name, created_at)`.
Never store raw HTML, cookies, headers with secrets, or passwords. Store IPs only as needed (no client IPs).

## 7. HTTP API - `backend/main.py` + `backend/api/*.py`

All JSON. Errors: `{"error": {"code": "...", "message": "..."}}` with proper status. CSRF: every state-changing
request (POST/PUT/PATCH/DELETE under /api) must carry header `X-Requested-With: PhishGuard` else 403.
Auth: JWT (HS256, `settings.JWT_SECRET`) in HttpOnly, SameSite=Lax cookie `pg_session` (Secure if
settings.COOKIE_SECURE); anonymous visitors get a random HttpOnly `pg_anon` cookie (stored hashed) so they can see
their own scans. Passwords: bcrypt (cost 12). Never return password hashes.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | /api/health | - | `{status:"ok", version, time, database:"ok", model_loaded, model_name}` |
| POST | /api/analyze | optional | body `{url}` -> report (200). 422 invalid URL (not stored). 429 rate-limited (Retry-After). 503 busy. |
| POST | /api/analyze/stream | optional | same, NDJSON stream: `{"type":"stage","stage":k,"label":l,"state":"started|done"}` ... `{"type":"result","report":{...}}` or `{"type":"error","error":{code,message}}` |
| GET | /api/history | optional | own scans (user, or anon session). `?page=1&page_size=20&q=&classification=` -> `{items:[{scan_id,url,hostname,created_at,risk_score,classification,confidence,status}], total, page, page_size}` |
| GET | /api/report/{scan_id} | owner/anon-owner/admin | full report JSON (404 if not visible) |
| GET | /api/report/{scan_id}/pdf | same | `application/pdf` download `PhishGuard-<scan_id>.pdf` |
| GET | /api/model/info | - | ML metrics/dataset/bias info from `ml/metrics.json` (+ `rules` list from rule engine) |
| POST | /api/auth/register | - | `{email,password}` -> 201 `{user}` + session cookie |
| POST | /api/auth/login | - | `{email,password}` -> `{user}` + cookie. Generic error on failure. Rate-limited per IP. |
| POST | /api/auth/logout | - | clears cookie |
| GET | /api/auth/me | - | `{user}` or 401 |
| POST | /api/auth/forgot-password | - | `{email}` -> always 200 generic message; token logged to server console if SMTP not configured |
| POST | /api/auth/reset-password | - | `{token,new_password}` |
| GET | /api/admin/stats | admin | `{totals:{total,phishing,suspicious,legitimate,failed}, daily:[{date,count}] (30 days), risk_distribution:[{range:"0-9",count}...10 buckets], recent:[{scan_id,url,classification,risk_score,created_at}] (10)}` |
| GET | /api/admin/scans | admin | paginated all scans (same item shape as history + user_email) |
| GET | /api/admin/users | admin | `[{id,email,role,created_at,last_login_at,scan_count}]` (no hashes) |

User object: `{id, email, role, created_at}`. Security headers middleware: CSP `default-src 'self'; img-src 'self' data:;
style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`,
X-Content-Type-Options nosniff, Referrer-Policy no-referrer, X-Frame-Options DENY, Permissions-Policy.
Static frontend mounted at `/` (html=True) AFTER API routes.

## 8. Frontend - `frontend/` (vanilla HTML/CSS/JS, no build step, no inline scripts/styles/handlers due to CSP)

Pages: `index.html` (landing + URL input), `scan.html?url=` (safety confirmation + live NDJSON progress),
`result.html?id=` (report), `history.html`, `dashboard.html` (admin), `login.html`, `register.html`,
`forgot-password.html`, `reset-password.html?token=`, `methodology.html` (Detection Methodology + Limitations + ML
metrics from /api/model/info).
CSS: `css/style.css` (design system + components), `css/dashboard.css` (dashboard/report layouts),
`css/responsive.css` (breakpoints 1200/992/768/480). JS: `js/app.js` (namespace `window.PG`: `PG.api(path,{method,body})`
auto-adds `X-Requested-With: PhishGuard` + JSON + credentials:'same-origin', throws `PG.ApiError{status,code,message}`;
`PG.el(tag, attrs, ...children)` safe DOM builder (text via textContent); `PG.auth.me()` cached; header/nav + footer
injection into `<div id="pg-header">`/`<div id="pg-footer">`; toasts; formatters `PG.fmt.date`, `PG.fmt.pct`;
`PG.classBadge(classification)`; `PG.riskColor(score)`), `js/scanner.js`, `js/result.js`, `js/history.js`,
`js/dashboard.js`, `js/auth.js`, `js/methodology.js`. Icons: inline SVG sprite `img/icons.svg` (`<use href>`).
Palette: navy #0B1220, emerald #16A34A, background #F8FAFC, warning #F59E0B, danger #DC2626, text #111827.
Enterprise SaaS look: cards, tables, badges, progress bars; NO hacker/matrix/neon/3D/skulls, minimal animation.
Charts: Chart.js from `vendor/chart.umd.min.js`.
