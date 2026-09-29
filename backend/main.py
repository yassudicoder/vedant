"""
PhishGuard FastAPI application.

- Security headers middleware
- CSRF protection for state-changing requests
- All API routers
- Static frontend mounted at "/" (after API routes)
- Database initialisation and optional admin bootstrap on startup
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings, FRONTEND_DIR
from backend.database import init_db, SessionLocal
from backend.api import auth_router, scan_router, admin_router, reports_router

logger = logging.getLogger("phishguard")

# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
)


# --------------------------------------------------------------------------- #
# Security headers middleware
# --------------------------------------------------------------------------- #

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# --------------------------------------------------------------------------- #
# CSRF middleware
# --------------------------------------------------------------------------- #

_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_HEADER = "x-requested-with"
_CSRF_VALUE = "PhishGuard"


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject state-changing requests under /api that lack the CSRF header."""

    async def dispatch(self, request: Request, call_next):
        if request.method in _CSRF_METHODS and request.url.path.startswith("/api"):
            header_val = request.headers.get(_CSRF_HEADER, "")
            if header_val != _CSRF_VALUE:
                return JSONResponse(
                    status_code=403,
                    content={"error": {"code": "CSRF_FAILED", "message": "Missing or invalid X-Requested-With header."}},
                )
        return await call_next(request)


app.add_middleware(CSRFMiddleware)


# --------------------------------------------------------------------------- #
# CORS (if configured)
# --------------------------------------------------------------------------- #

if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# --------------------------------------------------------------------------- #
# Routers
# --------------------------------------------------------------------------- #

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(admin_router)
app.include_router(reports_router)


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #

@app.on_event("startup")
def on_startup():
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s",
    )
    logger.info("PhishGuard %s starting (env=%s)", settings.APP_VERSION, settings.ENVIRONMENT)

    # Create tables
    init_db()
    logger.info("Database initialised")

    # Bootstrap admin user from env if configured
    if settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD and not settings.TESTING:
        _bootstrap_admin()


def _bootstrap_admin() -> None:
    """Create the admin user from environment variables if not already present."""
    from backend.api.auth import hash_password
    from backend.models import User

    db = SessionLocal()
    try:
        email = settings.ADMIN_EMAIL.lower().strip()
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            if existing.role != "admin":
                existing.role = "admin"
                db.commit()
                logger.info("Existing user %s promoted to admin", email)
            else:
                logger.info("Admin user %s already exists", email)
            return

        admin = User(
            email=email,
            password_hash=hash_password(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        logger.info("Admin user %s created from environment variables", email)
    except Exception:
        db.rollback()
        logger.exception("Failed to bootstrap admin user")
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Validation error handler (Pydantic)
# --------------------------------------------------------------------------- #

from fastapi.exceptions import RequestValidationError


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Extract a user-friendly message
    errors = exc.errors()
    if errors:
        first = errors[0]
        msg = first.get("msg", "Validation error.")
        # Strip pydantic prefix "Value error, " if present
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, "):]
    else:
        msg = "Validation error."
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "VALIDATION_ERROR", "message": msg}},
    )


# --------------------------------------------------------------------------- #
# Static frontend (mounted LAST so API routes take priority)
# --------------------------------------------------------------------------- #

if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
