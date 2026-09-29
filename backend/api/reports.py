"""
Reports API routes.

This module re-exports the report endpoints from scan.py for organisational
clarity. The actual route handlers live in backend.api.scan since reports are
tightly coupled to scan persistence. This file exists as required by the
project structure contract and provides a router that can be included
independently if the routes are ever separated.

Currently the report routes (/api/report/{scan_id} and /api/report/{scan_id}/pdf)
are registered directly on the scan router.
"""
from __future__ import annotations

from fastapi import APIRouter

# The report endpoints are registered on the scan router in backend.api.scan.
# This module provides an empty router so that backend/api/__init__.py can
# import it without error. If report routes need to be split out later, move
# them here.
router = APIRouter(tags=["reports"])
