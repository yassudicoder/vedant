"""
Admin API routes (require admin role).

GET /api/admin/stats  -- dashboard statistics
GET /api/admin/scans  -- paginated all scans
GET /api/admin/users  -- all users with scan counts
"""
from __future__ import annotations

import datetime as _dt

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func as sa_func
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import Scan, User
from backend.api.auth import require_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


# --------------------------------------------------------------------------- #
# GET /api/admin/stats
# --------------------------------------------------------------------------- #

@router.get("/stats")
def admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    # Totals
    total = db.query(sa_func.count(Scan.id)).scalar() or 0
    phishing = db.query(sa_func.count(Scan.id)).filter(Scan.classification == "PHISHING").scalar() or 0
    suspicious = db.query(sa_func.count(Scan.id)).filter(Scan.classification == "SUSPICIOUS").scalar() or 0
    legitimate = db.query(sa_func.count(Scan.id)).filter(Scan.classification == "LEGITIMATE").scalar() or 0
    failed = db.query(sa_func.count(Scan.id)).filter(Scan.classification == "ANALYSIS_FAILED").scalar() or 0

    totals = {
        "total": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "legitimate": legitimate,
        "failed": failed,
    }

    # Daily counts (last 30 days)
    now = _dt.datetime.now(_dt.timezone.utc)
    thirty_days_ago = now - _dt.timedelta(days=30)

    # Build daily counts using Python since SQLite date functions vary
    daily_rows = (
        db.query(Scan.created_at)
        .filter(Scan.created_at >= thirty_days_ago)
        .all()
    )
    daily_counts: dict[str, int] = {}
    for (created_at,) in daily_rows:
        if created_at:
            day = created_at.strftime("%Y-%m-%d")
            daily_counts[day] = daily_counts.get(day, 0) + 1

    # Fill in missing days
    daily = []
    for i in range(30):
        day = (now - _dt.timedelta(days=29 - i)).strftime("%Y-%m-%d")
        daily.append({"date": day, "count": daily_counts.get(day, 0)})

    # Risk distribution (10 buckets of 10)
    risk_distribution = []
    for bucket_start in range(0, 100, 10):
        bucket_end = bucket_start + 9
        label = f"{bucket_start}-{bucket_end}"
        count = (
            db.query(sa_func.count(Scan.id))
            .filter(Scan.risk_score != None, Scan.risk_score >= bucket_start, Scan.risk_score <= bucket_end)  # noqa: E711
            .scalar()
            or 0
        )
        risk_distribution.append({"range": label, "count": count})

    # Recent scans (10)
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    recent = [
        {
            "scan_id": s.public_id,
            "url": s.url,
            "classification": s.classification,
            "risk_score": s.risk_score,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent_scans
    ]

    return {
        "totals": totals,
        "daily": daily,
        "risk_distribution": risk_distribution,
        "recent": recent,
    }


# --------------------------------------------------------------------------- #
# GET /api/admin/scans
# --------------------------------------------------------------------------- #

@router.get("/scans")
def admin_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    q: str | None = Query(None),
    classification: str | None = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    query = db.query(Scan)

    if q:
        like_q = f"%{q}%"
        query = query.filter(
            (Scan.url.ilike(like_q)) | (Scan.hostname.ilike(like_q)) | (Scan.public_id.ilike(like_q))
        )

    if classification:
        query = query.filter(Scan.classification == classification.upper())

    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    # Pre-fetch user emails
    user_ids = {s.user_id for s in scans if s.user_id}
    users_map: dict[int, str] = {}
    if user_ids:
        users = db.query(User.id, User.email).filter(User.id.in_(user_ids)).all()
        users_map = {u.id: u.email for u in users}

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
            "user_email": users_map.get(s.user_id) if s.user_id else None,
        }
        for s in scans
    ]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


# --------------------------------------------------------------------------- #
# GET /api/admin/users
# --------------------------------------------------------------------------- #

@router.get("/users")
def admin_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).order_by(User.created_at.desc()).all()

    # Scan counts per user
    scan_counts_rows = (
        db.query(Scan.user_id, sa_func.count(Scan.id))
        .filter(Scan.user_id != None)  # noqa: E711
        .group_by(Scan.user_id)
        .all()
    )
    scan_counts = {uid: cnt for uid, cnt in scan_counts_rows}

    return [
        {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "scan_count": scan_counts.get(u.id, 0),
        }
        for u in users
    ]
