"""
Authentication API routes.

POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
POST /api/auth/forgot-password
POST /api/auth/reset-password
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import logging
import secrets

import bcrypt
import jwt
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import PasswordResetToken, User
from backend.security.rate_limiter import auth_ip_limiter, client_ip

logger = logging.getLogger("phishguard.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_BCRYPT_COST = 12


def _sha256_prehash(password: str) -> bytes:
    """SHA-256 pre-hash so bcrypt's 72-byte limit never silently truncates."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        _sha256_prehash(password),
        bcrypt.gensalt(rounds=_BCRYPT_COST),
    ).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_sha256_prehash(password), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: int, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=settings.ACCESS_TOKEN_MINUTES),
        "iat": _dt.datetime.now(_dt.timezone.utc),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=settings.ACCESS_TOKEN_MINUTES * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
    )


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    """Return the authenticated User or None (no 401)."""
    token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        return None
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
    return user


def get_current_user_required(request: Request, db: Session = Depends(get_db)) -> User:
    """Return the authenticated User or raise 401."""
    user = get_current_user_optional(request, db)
    if user is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail={"error": {"code": "UNAUTHORIZED", "message": "Authentication required."}})
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """Return the authenticated admin User or raise 403."""
    user = get_current_user_required(request, db)
    if user.role != "admin":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail={"error": {"code": "FORBIDDEN", "message": "Admin access required."}})
    return user


def get_anon_session_hash(request: Request) -> str | None:
    """Return the sha-256 hash of the anonymous session cookie, or None."""
    raw = request.cookies.get(settings.ANON_COOKIE_NAME)
    if not raw:
        return None
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def ensure_anon_cookie(request: Request, response: Response) -> str:
    """Return or create an anonymous session hash, setting the cookie if new."""
    raw = request.cookies.get(settings.ANON_COOKIE_NAME)
    if raw:
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    new_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.ANON_COOKIE_NAME,
        value=new_token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=60 * 60 * 24 * 365,  # 1 year
        path="/",
    )
    return hashlib.sha256(new_token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Request schemas
# --------------------------------------------------------------------------- #

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters.")
        return v


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return Response(
            status_code=409,
            content='{"error":{"code":"EMAIL_EXISTS","message":"An account with this email already exists."}}',
            media_type="application/json",
        )
    user = User(
        email=email,
        password_hash=hash_password(body.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id, user.role)
    set_session_cookie(response, token)
    return {"user": user.to_dict()}


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    # Rate-limit by IP
    ip = client_ip(request)
    allowed, retry_after = auth_ip_limiter.hit(ip)
    if not allowed:
        return Response(
            status_code=429,
            content='{"error":{"code":"RATE_LIMITED","message":"Too many login attempts. Please try again later."}}',
            media_type="application/json",
            headers={"Retry-After": str(retry_after)},
        )

    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()
    # Generic message to prevent user enumeration
    generic_error = '{"error":{"code":"INVALID_CREDENTIALS","message":"Invalid email or password."}}'
    if not user or not user.is_active:
        return Response(status_code=401, content=generic_error, media_type="application/json")
    if not verify_password(body.password, user.password_hash):
        return Response(status_code=401, content=generic_error, media_type="application/json")

    user.last_login_at = _dt.datetime.now(_dt.timezone.utc)
    db.commit()

    token = create_access_token(user.id, user.role)
    set_session_cookie(response, token)
    return {"user": user.to_dict()}


@router.post("/logout")
def logout(response: Response):
    clear_session_cookie(response)
    return {"status": "ok"}


@router.get("/me")
def me(user: User | None = Depends(get_current_user_optional)):
    if user is None:
        return Response(
            status_code=401,
            content='{"error":{"code":"UNAUTHORIZED","message":"Not authenticated."}}',
            media_type="application/json",
        )
    return {"user": user.to_dict()}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Always return 200 with a generic message regardless of whether the email exists."""
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email, User.is_active == True).first()  # noqa: E712

    if user:
        # Invalidate any existing unexpired tokens for this user
        now = _dt.datetime.now(_dt.timezone.utc)
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at == None,  # noqa: E711
        ).update({"used_at": now})

        raw_token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        reset = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now + _dt.timedelta(minutes=settings.RESET_TOKEN_MINUTES),
        )
        db.add(reset)
        db.commit()

        reset_url = f"{settings.PUBLIC_BASE_URL}/reset-password.html?token={raw_token}"
        if settings.SMTP_HOST:
            # TODO: send email via SMTP
            logger.info("Password reset email would be sent to %s", email)
        else:
            logger.info("Password reset link (SMTP not configured): %s", reset_url)

    return {"message": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    now = _dt.datetime.now(_dt.timezone.utc)

    reset = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used_at == None,  # noqa: E711
        PasswordResetToken.expires_at > now,
    ).first()

    if not reset:
        return Response(
            status_code=400,
            content='{"error":{"code":"INVALID_TOKEN","message":"This reset link is invalid or has expired."}}',
            media_type="application/json",
        )

    user = db.query(User).filter(User.id == reset.user_id).first()
    if not user or not user.is_active:
        return Response(
            status_code=400,
            content='{"error":{"code":"INVALID_TOKEN","message":"This reset link is invalid or has expired."}}',
            media_type="application/json",
        )

    user.password_hash = hash_password(body.new_password)
    reset.used_at = now
    db.commit()

    return {"message": "Password has been reset successfully."}
