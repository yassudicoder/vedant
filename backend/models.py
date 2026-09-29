"""
PhishGuard SQLAlchemy ORM models.

Tables
------
- users              -- registered accounts
- password_reset_tokens -- time-limited reset tokens (sha-256 hashed)
- scans              -- one row per analysis run
- scan_features      -- extracted numeric/boolean features (1:1 with scans)
- scan_results       -- summary + full report JSON (1:1 with scans)
"""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from backend.database import Base


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(320), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(16), nullable=False, default="user")  # 'user' | 'admin'
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    last_login_at = Column(DateTime, nullable=True)

    # relationships
    scans = relationship("Scan", back_populates="user", lazy="dynamic")
    reset_tokens = relationship("PasswordResetToken", back_populates="user", lazy="dynamic")

    def to_dict(self) -> dict:
        """Public representation -- never includes password_hash."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# --------------------------------------------------------------------------- #
# Password reset tokens
# --------------------------------------------------------------------------- #

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, index=True)  # sha-256 hex
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())

    user = relationship("User", back_populates="reset_tokens")


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    public_id = Column(String(20), unique=True, nullable=False, index=True)  # SCAN-YYYY-NNNNN
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    anon_session_hash = Column(String(64), nullable=True, index=True)

    url = Column(Text, nullable=False)
    normalized_url = Column(Text, nullable=True)
    final_url = Column(Text, nullable=True)
    hostname = Column(String(512), nullable=True)
    registered_domain = Column(String(512), nullable=True)

    status = Column(String(32), nullable=False)  # completed | partial | failed
    classification = Column(String(32), nullable=True)  # LEGITIMATE | SUSPICIOUS | PHISHING | ANALYSIS_FAILED
    risk_score = Column(Integer, nullable=True)
    confidence = Column(Integer, nullable=True)
    risk_band = Column(String(16), nullable=True)

    error_code = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())

    # relationships (one-to-one children)
    user = relationship("User", back_populates="scans")
    features = relationship("ScanFeatures", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    result = relationship("ScanResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")


# --------------------------------------------------------------------------- #
# Scan features (1:1 with scans)
# --------------------------------------------------------------------------- #

class ScanFeatures(Base):
    __tablename__ = "scan_features"

    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)

    url_length = Column(Integer, nullable=True)
    domain_length = Column(Integer, nullable=True)
    num_dots = Column(Integer, nullable=True)
    num_hyphens = Column(Integer, nullable=True)
    num_subdomains = Column(Integer, nullable=True)
    has_ip = Column(Boolean, nullable=True)
    has_at_symbol = Column(Boolean, nullable=True)
    has_https = Column(Boolean, nullable=True)
    num_redirects = Column(Integer, nullable=True)
    suspicious_keyword_count = Column(Integer, nullable=True)
    external_link_ratio = Column(Float, nullable=True)
    form_count = Column(Integer, nullable=True)
    iframe_count = Column(Integer, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    certificate_valid = Column(Boolean, nullable=True)
    punycode_detected = Column(Boolean, nullable=True)
    query_parameter_count = Column(Integer, nullable=True)
    path_length = Column(Integer, nullable=True)
    special_character_count = Column(Integer, nullable=True)
    ml_features_json = Column(Text, nullable=True)  # JSON blob of all ML feature values

    scan = relationship("Scan", back_populates="features")


# --------------------------------------------------------------------------- #
# Scan results (1:1 with scans)
# --------------------------------------------------------------------------- #

class ScanResult(Base):
    __tablename__ = "scan_results"

    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)

    summary = Column(Text, nullable=True)
    report_json = Column(Text, nullable=False)  # full report serialised as JSON
    ml_probability_phishing = Column(Float, nullable=True)
    model_name = Column(String(128), nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())

    scan = relationship("Scan", back_populates="result")
