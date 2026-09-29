"""
PhishGuard ML inference service.

Loads the trained model lazily (thread-safe) and exposes:
  - predict(ml_features) -> dict   used by the analysis pipeline
  - get_model_info() -> dict       used by /api/model/info and /api/health
"""
from __future__ import annotations

import json
import logging
import pickle
import threading
from pathlib import Path
from typing import Any

from backend.config import settings
from backend.services.common import make_finding
from ml.feature_extractor import ML_FEATURE_NAMES, features_to_vector

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Lazy, thread-safe model loading
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_model_artifact: dict[str, Any] | None = None
_model_loaded: bool = False
_load_error: str | None = None


def _load_model() -> None:
    """Load the model artifact from disk. Called once under _lock."""
    global _model_artifact, _model_loaded, _load_error

    model_path = Path(settings.ML_MODEL_PATH)
    if not model_path.exists():
        _load_error = f"Model file not found: {model_path}"
        logger.warning(_load_error)
        return

    try:
        with open(str(model_path), "rb") as f:
            artifact = pickle.load(f)

        # Validate artifact structure
        required_keys = {"model", "feature_names", "model_name", "model_version"}
        if not isinstance(artifact, dict) or not required_keys.issubset(artifact.keys()):
            _load_error = "Model artifact is missing required keys."
            logger.error(_load_error)
            return

        # Verify feature compatibility
        if tuple(artifact["feature_names"]) != ML_FEATURE_NAMES:
            _load_error = (
                f"Feature mismatch: model expects {artifact['feature_names']}, "
                f"current code defines {ML_FEATURE_NAMES}"
            )
            logger.error(_load_error)
            return

        # Verify predict and predict_proba exist
        model = artifact["model"]
        if not hasattr(model, "predict") or not hasattr(model, "predict_proba"):
            _load_error = "Model object lacks predict/predict_proba methods."
            logger.error(_load_error)
            return

        _model_artifact = artifact
        _model_loaded = True
        logger.info(
            "ML model loaded: %s v%s (trained %s)",
            artifact.get("model_name"),
            artifact.get("model_version"),
            artifact.get("trained_at", "unknown"),
        )

    except Exception as exc:
        _load_error = f"Failed to load model: {exc}"
        logger.error(_load_error, exc_info=True)


def _ensure_model() -> dict[str, Any] | None:
    """Return the model artifact, loading it on first call. Thread-safe."""
    global _model_loaded
    if not _model_loaded and _load_error is None:
        with _lock:
            # Double-check after acquiring lock
            if not _model_loaded and _load_error is None:
                _load_model()
    return _model_artifact


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def get_model_info() -> dict[str, Any]:
    """
    Return model metadata for /api/model/info and /api/health.

    Combines the contents of metrics.json with the live loaded status.
    """
    info: dict[str, Any] = {"loaded": False, "model_name": None, "model_version": None}

    # Try to load metrics.json
    metrics_path = Path(settings.ML_METRICS_PATH)
    if metrics_path.exists():
        try:
            with open(str(metrics_path), "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
            info.update(metrics_data)
        except Exception as exc:
            info["metrics_error"] = str(exc)

    # Add live model status
    artifact = _ensure_model()
    if artifact is not None:
        info["loaded"] = True
        info["model_name"] = artifact.get("model_name")
        info["model_version"] = artifact.get("model_version")
    else:
        info["loaded"] = False
        if _load_error:
            info["load_error"] = _load_error

    return info


def predict(ml_features: dict[str, float]) -> dict[str, Any]:
    """
    Run the ML model on pre-extracted host-lexical features.

    Parameters
    ----------
    ml_features : dict
        Feature dict keyed by ML_FEATURE_NAMES, as returned by
        extract_ml_features().

    Returns
    -------
    dict
        Full prediction result conforming to BUILD_CONTRACT section 3.7.
    """
    findings: list[dict] = []

    # Base response skeleton
    result: dict[str, Any] = {
        "status": "unavailable",
        "message": None,
        "model_name": None,
        "model_version": None,
        "trained_at": None,
        "dataset": None,
        "feature_set": "host-lexical-v1",
        "probability_phishing": None,
        "probability_legitimate": None,
        "ml_verdict": None,
        "thresholds": {
            "suspicious": settings.ML_SUSPICIOUS_THRESHOLD,
            "phishing": settings.ML_PHISHING_THRESHOLD,
        },
        "top_features": [],
        "features": ml_features,
        "note": (
            "The model is binary (legitimate vs phishing). "
            "SUSPICIOUS is a probability band, not a learned class."
        ),
        "findings": findings,
    }

    # Load model
    artifact = _ensure_model()
    if artifact is None:
        result["message"] = _load_error or "ML model is not available."
        return result

    model = artifact["model"]
    result["model_name"] = artifact.get("model_name")
    result["model_version"] = artifact.get("model_version")
    result["trained_at"] = artifact.get("trained_at")
    result["dataset"] = artifact.get("dataset")

    try:
        # Build feature vector in the correct order
        vector = features_to_vector(ml_features)
        import numpy as np
        X = np.array([vector], dtype=np.float64)

        # Predict
        probabilities = model.predict_proba(X)[0]
        # Model classes: 0=phishing, 1=legitimate
        classes = list(model.classes_)
        idx_phishing = classes.index(0) if 0 in classes else 0
        idx_legitimate = classes.index(1) if 1 in classes else 1

        prob_phishing = float(probabilities[idx_phishing])
        prob_legitimate = float(probabilities[idx_legitimate])

        result["status"] = "ok"
        result["message"] = None
        result["probability_phishing"] = round(prob_phishing, 6)
        result["probability_legitimate"] = round(prob_legitimate, 6)

        # ML verdict based on thresholds
        if prob_phishing >= settings.ML_PHISHING_THRESHOLD:
            result["ml_verdict"] = "PHISHING"
        elif prob_phishing >= settings.ML_SUSPICIOUS_THRESHOLD:
            result["ml_verdict"] = "SUSPICIOUS"
        else:
            result["ml_verdict"] = "LEGITIMATE"

        # Top features: global importance * feature presence value
        feature_importances = artifact.get("feature_importances", [])
        if feature_importances:
            scored = []
            for fi in feature_importances:
                fname = fi["feature"]
                importance = fi["importance"]
                value = ml_features.get(fname, 0.0)
                # Score = global importance * presence (abs value for ranking)
                score = importance * abs(value)
                scored.append({
                    "feature": fname,
                    "value": round(float(value), 6),
                    "importance": round(float(importance), 6),
                    "_score": score,
                })
            scored.sort(key=lambda x: x["_score"], reverse=True)
            result["top_features"] = [
                {"feature": s["feature"], "value": s["value"], "importance": s["importance"]}
                for s in scored[:6]
            ]

        # Findings based on probability
        if prob_phishing >= settings.ML_PHISHING_THRESHOLD:
            findings.append(make_finding(
                "ml.high_probability",
                "medium",
                "ml",
                f"ML model indicates high phishing probability ({prob_phishing:.0%}).",
                detail=f"Model: {result['model_name']}, probability: {prob_phishing:.4f}",
                points=0.0,  # Risk engine uses probability directly, not finding points
                source="ml_detector",
            ))
        elif prob_phishing >= settings.ML_SUSPICIOUS_THRESHOLD:
            findings.append(make_finding(
                "ml.moderate_probability",
                "low",
                "ml",
                f"ML model indicates moderate phishing probability ({prob_phishing:.0%}).",
                detail=f"Model: {result['model_name']}, probability: {prob_phishing:.4f}",
                points=0.0,
                source="ml_detector",
            ))
        else:
            findings.append(make_finding(
                "ml.low_probability",
                "info",
                "ml",
                f"ML model indicates low phishing probability ({prob_phishing:.0%}).",
                detail=f"Model: {result['model_name']}, probability: {prob_phishing:.4f}",
                points=0.0,
                source="ml_detector",
            ))

    except Exception as exc:
        logger.error("ML prediction failed: %s", exc, exc_info=True)
        result["status"] = "error"
        result["message"] = f"Prediction failed: {exc}"

    return result
