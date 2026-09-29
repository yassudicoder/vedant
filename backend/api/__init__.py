"""
PhishGuard API package.

Exposes all sub-routers for inclusion by backend.main.
"""
from backend.api.auth import router as auth_router
from backend.api.scan import router as scan_router
from backend.api.admin import router as admin_router
from backend.api.reports import router as reports_router

__all__ = ["auth_router", "scan_router", "admin_router", "reports_router"]
