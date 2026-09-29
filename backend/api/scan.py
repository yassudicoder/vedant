"""
Scan / analysis API routes.

POST /api/analyze         -- synchronous analysis
POST /api/analyze/stream  -- NDJSON streaming analysis
GET  /api/history         -- own scans (user or anon)
GET  /api/report/{id}     -- full report
GET  /api/report/{id}/pdf -- PDF download
GET  /api/health          -- health check
GET  /api/model/info      -- ML model metadata + rule list
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func as sa_func
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import SessionLocal, get_db
from backend.models import Scan, ScanFeatures, ScanResult, User
from backend.api.auth import (
    ensure_anon_cookie,
    get_anon_session_hash,
    get_current_user_optional,
)
from backend.security.rate_limiter import (
    client_ip,
    scan_concurrency,
    scan_ip_limiter,
    scan_session_limiter,
)

logger = logging.getLogger("phishguard.scan")

router = APIRouter(tags=["scan"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _next_public_id(db: Session) -> str:
    """Generate the next SCAN-YYYY-NNNNN id."""
    year = _dt.datetime.now(_dt.timezone.utc).year
    prefix = f"SCAN-{year}-"
    last = (
        db.query(Scan.public_id)
        .filter(Scan.public_id.like(f"{prefix}%"))
        .order_by(Scan.id.desc())
        .first()
    )
    if last:
        try:
            seq = int(last[0].split("-")[-1]) + 1
        except (ValueError, IndexError):
            seq = 1
    else:
        seq = 1
    return f"{prefix}{seq:05d}"


def _persist_scan(
    db: Session,
    report: dict,
    public_id: str,
    user_id: int | None,
    anon_hash: str | None,
) -> Scan:
    """Write a completed report to the database."""
    scan = Scan(
        public_id=public_id,
        user_id=user_id,
        anon_session_hash=anon_hash,
        url=report.get("url", ""),
        normalized_url=report.get("normalized_url"),
        final_url=report.get("final_url"),
        hostname=report.get("url_analysis", {}).get("hostname") if isinstance(report.get("url_analysis"), dict) else None,
        registered_domain=report.get("url_analysis", {}).get("registered_domain") if isinstance(report.get("url_analysis"), dict) else None,
        status=report.get("status", "failed"),
        classification=report.get("classification"),
        risk_score=report.get("risk_score"),
        confidence=report.get("confidence"),
        risk_band=report.get("risk_band"),
        error_code=report.get("error", {}).get("code") if isinstance(report.get("error"), dict) else None,
        error_message=report.get("error", {}).get("message") if isinstance(report.get("error"), dict) else None,
        duration_ms=report.get("duration_ms"),
    )
    db.add(scan)
    db.flush()  # get scan.id

    # Features
    url_a = report.get("url_analysis") if isinstance(report.get("url_analysis"), dict) else {}
    redirect_a = report.get("redirect_analysis") if isinstance(report.get("redirect_analysis"), dict) else {}
    webpage_a = report.get("webpage_analysis") if isinstance(report.get("webpage_analysis"), dict) else {}
    tls_a = report.get("tls_analysis") if isinstance(report.get("tls_analysis"), dict) else {}
    domain_a = report.get("domain_analysis") if isinstance(report.get("domain_analysis"), dict) else {}

    features = ScanFeatures(
        scan_id=scan.id,
        url_length=url_a.get("url_length"),
        domain_length=url_a.get("domain_length"),
        num_dots=url_a.get("num_dots"),
        num_hyphens=url_a.get("num_hyphens"),
        num_subdomains=url_a.get("num_subdomains"),
        has_ip=url_a.get("has_ip"),
        has_at_symbol=url_a.get("has_at_symbol"),
        has_https=url_a.get("https", None) if isinstance(url_a.get("https"), bool) else None,
        num_redirects=redirect_a.get("num_redirects"),
        suspicious_keyword_count=url_a.get("suspicious_keyword_count"),
        external_link_ratio=webpage_a.get("links", {}).get("external_ratio") if isinstance(webpage_a.get("links"), dict) else None,
        form_count=webpage_a.get("forms", {}).get("count") if isinstance(webpage_a.get("forms"), dict) else None,
        iframe_count=webpage_a.get("iframes", {}).get("count") if isinstance(webpage_a.get("iframes"), dict) else None,
        domain_age_days=domain_a.get("registration", {}).get("domain_age_days") if isinstance(domain_a.get("registration"), dict) else None,
        certificate_valid=tls_a.get("certificate_valid"),
        punycode_detected=url_a.get("has_punycode"),
        query_parameter_count=url_a.get("num_query_params"),
        path_length=url_a.get("path_length"),
        special_character_count=url_a.get("num_special_chars"),
        ml_features_json=json.dumps(url_a.get("ml_features")) if url_a.get("ml_features") else None,
    )
    db.add(features)

    ml_a = report.get("ml_analysis") if isinstance(report.get("ml_analysis"), dict) else {}
    result = ScanResult(
        scan_id=scan.id,
        summary=report.get("summary"),
        report_json=json.dumps(report, default=str),
        ml_probability_phishing=ml_a.get("probability_phishing"),
        model_name=ml_a.get("model_name"),
    )
    db.add(result)
    db.commit()
    db.refresh(scan)
    return scan


def _rate_check(request: Request, response: Response) -> Response | None:
    """Check IP and session rate limits. Returns an error Response or None."""
    ip = client_ip(request)
    allowed, retry_after = scan_ip_limiter.hit(ip)
    if not allowed:
        return Response(
            status_code=429,
            content=json.dumps({"error": {"code": "RATE_LIMITED", "message": "Too many requests. Please try again later."}}),
            media_type="application/json",
            headers={"Retry-After": str(retry_after)},
        )

    session_key = get_anon_session_hash(request) or ip
    allowed, retry_after = scan_session_limiter.hit(session_key)
    if not allowed:
        return Response(
            status_code=429,
            content=json.dumps({"error": {"code": "RATE_LIMITED", "message": "Too many requests. Please try again later."}}),
            media_type="application/json",
            headers={"Retry-After": str(retry_after)},
        )
    return None


# --------------------------------------------------------------------------- #
# Request schemas
# --------------------------------------------------------------------------- #

class AnalyzeRequest(BaseModel):
    url: str


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #

@router.get("/api/health")
def health():
    from backend.services.ml_detector import get_model_info

    db_ok = True
    try:
        db = SessionLocal()
        try:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
        finally:
            db.close()
    except Exception:
        db_ok = False

    info = get_model_info()
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "time": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "database": "ok" if db_ok else "error",
        "model_loaded": info.get("loaded", False),
        "model_name": info.get("model_name"),
    }


# --------------------------------------------------------------------------- #
# Model info
# --------------------------------------------------------------------------- #

@router.get("/api/model/info")
def model_info():
    from backend.services.ml_detector import get_model_info
    from backend.services.rule_engine import list_rules

    info = get_model_info()
    info["rules"] = list_rules()
    return info


# --------------------------------------------------------------------------- #
# POST /api/analyze
# --------------------------------------------------------------------------- #

@router.post("/api/analyze")
def analyze(
    body: AnalyzeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
):
    from backend.security.validation import URLValidationError
    from backend.services.analysis_pipeline import run_analysis

    rate_resp = _rate_check(request, response)
    if rate_resp:
        return rate_resp

    if not scan_concurrency.try_acquire():
        return Response(
            status_code=503,
            content='{"error":{"code":"BUSY","message":"Server is busy. Please try again in a moment."}}',
            media_type="application/json",
        )

    try:
        anon_hash = ensure_anon_cookie(request, response) if user is None else None
        public_id = _next_public_id(db)

        try:
            report = run_analysis(body.url)
        except URLValidationError as exc:
            return Response(
                status_code=422,
                content=json.dumps({"error": {"code": exc.code, "message": exc.message}}),
                media_type="application/json",
            )

        now = _dt.datetime.now(_dt.timezone.utc)
        report["scan_id"] = public_id
        report["created_at"] = now.isoformat()

        _persist_scan(db, report, public_id, user.id if user else None, anon_hash)
        return report
    finally:
        scan_concurrency.release()


# --------------------------------------------------------------------------- #
# POST /api/analyze/stream  (NDJSON)
# --------------------------------------------------------------------------- #

@router.post("/api/analyze/stream")
def analyze_stream(
    body: AnalyzeRequest,
    request: Request,
    response: Response,
    user: User | None = Depends(get_current_user_optional),
):
    from backend.security.validation import URLValidationError
    from backend.services.analysis_pipeline import STAGES, run_analysis

    rate_resp = _rate_check(request, response)
    if rate_resp:
        return rate_resp

    if not scan_concurrency.try_acquire():
        return Response(
            status_code=503,
            content='{"error":{"code":"BUSY","message":"Server is busy. Please try again in a moment."}}',
            media_type="application/json",
        )

    anon_hash: str | None = None
    anon_cookie_value: str | None = None
    if user is None:
        raw = request.cookies.get(settings.ANON_COOKIE_NAME)
        if raw:
            anon_hash = hashlib.sha256(raw.encode()).hexdigest()
        else:
            import secrets as _secrets
            anon_cookie_value = _secrets.token_urlsafe(32)
            anon_hash = hashlib.sha256(anon_cookie_value.encode()).hexdigest()

    def _stream():
        try:

            def progress(stage_key: str, state: str) -> None:
                label = dict(STAGES).get(stage_key, stage_key)
                line = json.dumps({"type": "stage", "stage": stage_key, "label": label, "state": state})
                progress._lines.append(line + "\n")

            progress._lines = []  # type: ignore[attr-defined]

            try:
                report = run_analysis(body.url, progress=progress)
            except URLValidationError as exc:
                yield json.dumps({"type": "error", "error": {"code": exc.code, "message": exc.message}}) + "\n"
                return

            # Yield accumulated stage events
            for line in progress._lines:  # type: ignore[attr-defined]
                yield line

            # Persist
            db = SessionLocal()
            try:
                public_id = _next_public_id(db)
                now = _dt.datetime.now(_dt.timezone.utc)
                report["scan_id"] = public_id
                report["created_at"] = now.isoformat()
                _persist_scan(db, report, public_id, user.id if user else None, anon_hash)
            finally:
                db.close()

            yield json.dumps({"type": "result", "report": report}, default=str) + "\n"
        finally:
            scan_concurrency.release()

    resp = StreamingResponse(_stream(), media_type="application/x-ndjson")
    if anon_cookie_value:
        resp.set_cookie(
            key=settings.ANON_COOKIE_NAME,
            value=anon_cookie_value,
            httponly=True,
            samesite="lax",
            secure=settings.COOKIE_SECURE,
            max_age=60 * 60 * 24 * 365,
            path="/",
        )
    return resp


# --------------------------------------------------------------------------- #
# GET /api/history
# --------------------------------------------------------------------------- #

@router.get("/api/history")
def history(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: str | None = Query(None),
    classification: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
):
    query = db.query(Scan)

    if user:
        query = query.filter(Scan.user_id == user.id)
    else:
        anon_hash = get_anon_session_hash(request)
        if not anon_hash:
            return {"items": [], "total": 0, "page": page, "page_size": page_size}
        query = query.filter(Scan.anon_session_hash == anon_hash)

    if q:
        like_q = f"%{q}%"
        query = query.filter(
            (Scan.url.ilike(like_q)) | (Scan.hostname.ilike(like_q)) | (Scan.public_id.ilike(like_q))
        )

    if classification:
        query = query.filter(Scan.classification == classification.upper())

    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    items = [
        {
            "scan_id": s.public_id,
            "url": s.url,
            "hostname": s.hostname,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "risk_score": s.risk_score,
            "classification": s.classification,
            "confidence": s.confidence,
            "status": s.status,
        }
        for s in scans
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


# --------------------------------------------------------------------------- #
# GET /api/report/{scan_id}
# --------------------------------------------------------------------------- #

@router.get("/api/report/{scan_id}")
def get_report(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
):
    scan = db.query(Scan).filter(Scan.public_id == scan_id).first()
    if not scan:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
            media_type="application/json",
        )

    # Ownership check
    if user and user.role == "admin":
        pass  # admin can see everything
    elif user and scan.user_id == user.id:
        pass  # owner
    elif not user and scan.anon_session_hash:
        anon_hash = get_anon_session_hash(request)
        if scan.anon_session_hash != anon_hash:
            return Response(
                status_code=404,
                content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
                media_type="application/json",
            )
    else:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
            media_type="application/json",
        )

    if not scan.result:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report data not available."}}',
            media_type="application/json",
        )

    try:
        report = json.loads(scan.result.report_json)
    except (json.JSONDecodeError, TypeError):
        return Response(
            status_code=500,
            content='{"error":{"code":"INTERNAL","message":"Report data corrupted."}}',
            media_type="application/json",
        )
    return report


# --------------------------------------------------------------------------- #
# GET /api/report/{scan_id}/pdf
# --------------------------------------------------------------------------- #

@router.get("/api/report/{scan_id}/pdf")
def get_report_pdf(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
):
    import tempfile
    from pathlib import Path
    from backend.config import REPORTS_DIR
    from backend.services.report_generator import generate_pdf

    scan = db.query(Scan).filter(Scan.public_id == scan_id).first()
    if not scan:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
            media_type="application/json",
        )

    # Same ownership check
    if user and user.role == "admin":
        pass
    elif user and scan.user_id == user.id:
        pass
    elif not user and scan.anon_session_hash:
        anon_hash = get_anon_session_hash(request)
        if scan.anon_session_hash != anon_hash:
            return Response(
                status_code=404,
                content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
                media_type="application/json",
            )
    else:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report not found."}}',
            media_type="application/json",
        )

    if not scan.result:
        return Response(
            status_code=404,
            content='{"error":{"code":"NOT_FOUND","message":"Report data not available."}}',
            media_type="application/json",
        )

    try:
        report = json.loads(scan.result.report_json)
    except (json.JSONDecodeError, TypeError):
        return Response(
            status_code=500,
            content='{"error":{"code":"INTERNAL","message":"Report data corrupted."}}',
            media_type="application/json",
        )

    pdf_path = str(REPORTS_DIR / f"PhishGuard-{scan_id}.pdf")
    try:
        generate_pdf(report, pdf_path)
        pdf_bytes = Path(pdf_path).read_bytes()
    except Exception:
        logger.exception("PDF generation failed for %s", scan_id)
        return Response(
            status_code=500,
            content='{"error":{"code":"PDF_ERROR","message":"Failed to generate PDF report."}}',
            media_type="application/json",
        )
    finally:
        # Clean up the file
        try:
            Path(pdf_path).unlink(missing_ok=True)
        except OSError:
            pass

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="PhishGuard-{scan_id}.pdf"',
        },
    )
