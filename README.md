# PhishGuard - URL Safety Analysis Tool

A research-oriented phishing detection web application that analyzes publicly accessible URLs using multi-layer security analysis, machine learning, and expert-crafted rules.

Built as a BCA final-year academic project.

## Features

- **URL Analysis** — lexical structure, suspicious patterns, encoding tricks, shortener detection
- **Domain Intelligence** — RDAP/WHOIS registration data, DNS records, ASN lookup, Tranco popularity ranking
- **TLS Inspection** — certificate validation, issuer classification, expiry checks
- **Webpage Analysis** — form detection (login/payment), hidden elements, suspicious scripts, brand mentions
- **Brand Impersonation** — typosquatting detection (edit distance, homoglyphs, combosquatting, punycode)
- **ML Detection** — RandomForest model trained on 235K+ URLs (PhiUSIIL dataset) with host-lexical features
- **Rule Engine** — 15 data-declared multi-signal combination rules (no single-feature verdicts)
- **Risk Scoring** — weighted component fusion with saturating formula, explainable findings
- **PDF Reports** — downloadable security reports via ReportLab
- **User Auth** — JWT in HttpOnly cookies, bcrypt passwords, anonymous session tracking
- **Admin Dashboard** — scan statistics, daily trends, risk distribution charts, user management

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.14, FastAPI 0.115, SQLAlchemy 2.x, Pydantic 2.x |
| Frontend | Vanilla HTML5/CSS3/JS (strict CSP, no inline scripts) |
| ML | scikit-learn (RandomForest), XGBoost, numpy |
| Database | SQLite (WAL mode), PostgreSQL compatible |
| Charts | Chart.js 4.4.7 (local copy) |
| PDF | ReportLab Platypus |
| DNS/Domain | dnspython, python-whois, tldextract |
| Security | SSRF-safe fetching with DNS-rebinding protection, rate limiting |

## Quick Start

```bash
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Train the ML model (one-time, ~20 seconds)
python -m ml.train

# Configure (optional)
cp .env.example .env
# Edit .env as needed (defaults work for local development)

# Run the server
python -m uvicorn backend.main:app --reload

# Open http://localhost:8000 in your browser
```

## Project Structure

```
phishguard/
├── backend/
│   ├── api/              # FastAPI route handlers
│   │   ├── auth.py       # Authentication (register/login/logout)
│   │   ├── scan.py       # Scan, report, health, model info
│   │   └── admin.py      # Admin dashboard API
│   ├── security/         # Security layer
│   │   ├── validation.py # URL normalization, host policy, IP detection
│   │   ├── ssrf_protection.py  # SSRF-safe fetch with IP pinning
│   │   └── rate_limiter.py     # Sliding window + concurrency limiters
│   ├── services/         # Analysis engines
│   │   ├── url_analyzer.py       # URL lexical analysis
│   │   ├── redirect_analyzer.py  # Redirect chain analysis
│   │   ├── tls_analyzer.py       # TLS/certificate analysis
│   │   ├── webpage_analyzer.py   # HTML page analysis
│   │   ├── brand_detector.py     # Brand impersonation detection
│   │   ├── domain_analyzer.py    # Domain intelligence (RDAP/DNS/ASN)
│   │   ├── ml_detector.py        # ML model inference
│   │   ├── rule_engine.py        # Multi-signal combination rules
│   │   ├── risk_engine.py        # Risk score computation
│   │   ├── analysis_pipeline.py  # Orchestrates full analysis
│   │   └── report_generator.py   # PDF report generation
│   ├── config.py         # Settings (env-var driven)
│   ├── database.py       # SQLAlchemy setup
│   ├── models.py         # Database models
│   └── main.py           # FastAPI application
├── frontend/
│   ├── css/              # Design system + responsive styles
│   ├── js/               # Page-specific JavaScript modules
│   ├── img/              # SVG icon sprite
│   ├── vendor/           # Chart.js local copy
│   └── *.html            # Pages (landing, scan, result, history, etc.)
├── ml/
│   ├── dataset/          # PhiUSIIL dataset (zip)
│   ├── train.py          # Training pipeline
│   ├── feature_extractor.py  # Shared feature extraction
│   ├── model.pkl         # Trained model artifact
│   └── metrics.json      # Evaluation metrics
├── reports/              # Generated PDF reports
├── tests/                # Test suite
├── docs/                 # Internal documentation
├── requirements.txt
├── pytest.ini
└── .env.example
```

## ML Model

The model is trained on the [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/) (235,795 URLs).

**Important bias mitigation**: The dataset has collection artifacts (all legitimate URLs are bare homepages with https+www; phishing URLs have paths and http). The model uses **only 21 host-lexical features** computed after stripping `www`, avoiding scheme/path/query features entirely.

| Metric | Value |
|--------|-------|
| Accuracy | 83.5% |
| F1 Score | 0.883 |
| ROC-AUC | 0.834 |
| Training split | GroupShuffleSplit by registered domain |

Top features by importance: `num_subdomains`, `subdomain_length`, `suspicious_tld`, `domain_entropy`, `num_digits`.

## Risk Scoring

The final risk score (0-100) is a weighted combination of four components:

- **ML** — model's phishing probability
- **Rules** — sum of URL, redirect, and rule-engine finding points (saturated)
- **Webpage** — sum of webpage and brand finding points (saturated)
- **Domain** — sum of domain, TLS, and reputation finding points (saturated)

Saturation formula: `100 × (1 - e^(-max(p, 0) / 45))`, preventing any single analyzer from dominating.

Classification bands: Low (<30) → LEGITIMATE, Moderate (30-59) → SUSPICIOUS, High (60-79) → PHISHING, Critical (80+) → PHISHING.

## Security

- **SSRF Protection** — DNS-rebinding-safe IP pinning via custom httpcore backend; blocks private/reserved/metadata IPs
- **CSP** — strict Content Security Policy (no inline scripts/styles/handlers)
- **CSRF** — `X-Requested-With: PhishGuard` header required on all state-changing requests
- **Auth** — JWT in HttpOnly SameSite=Lax cookies; bcrypt with sha256 pre-hash
- **Rate Limiting** — sliding window per IP and per session; concurrency limiting
- **Input Validation** — URL normalization with obfuscated IP detection (decimal, hex, octal, IPv4-mapped)
- **Output Escaping** — textContent-only DOM insertion; XML-escaped PDF text; truncated untrusted strings

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/analyze` | Analyze a URL (synchronous) |
| POST | `/api/analyze/stream` | Analyze with NDJSON progress |
| GET | `/api/history` | User's scan history |
| GET | `/api/report/{id}` | Full report JSON |
| GET | `/api/report/{id}/pdf` | Download PDF report |
| GET | `/api/model/info` | ML model metadata + rules |
| POST | `/api/auth/register` | Register |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Current user |
| GET | `/api/admin/stats` | Admin statistics |
| GET | `/api/admin/scans` | Admin scan list |
| GET | `/api/admin/users` | Admin user list |

## Configuration

All settings are environment-variable driven. See `.env.example` for the full list. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | (required) | Secret key for JWT signing |
| `DATABASE_URL` | `sqlite:///phishguard.db` | Database connection string |
| `ADMIN_EMAIL` | — | Bootstrap admin account email |
| `ADMIN_PASSWORD` | — | Bootstrap admin account password |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Optional Google Safe Browsing API key |
| `SCAN_TOTAL_TIMEOUT` | `30` | Maximum seconds per scan |

## Testing

```bash
# Run offline tests
python -m pytest -q

# Run with network tests
python -m pytest -q --run-network
```

## Limitations

- The ML model was trained on a specific dataset and may not recognize novel phishing techniques
- Domain registration data may be incomplete or unavailable for certain TLDs
- Pages behind authentication, CAPTCHAs, or bot detection cannot be fully analyzed
- A valid HTTPS certificate does not guarantee trustworthiness
- The tool does not submit forms, bypass access controls, or interact with page functionality
- Automated detection is probabilistic and should not be treated as definitive proof

## Disclaimer

This automated assessment is based on available technical signals and should not be treated as definitive proof of website legitimacy or maliciousness. PhishGuard is for educational and research purposes.

## License

Academic project — all rights reserved.
