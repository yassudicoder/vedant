"""
PhishGuard ML model training script.

Trains a phishing-detection model on host-lexical features only, using the
PhiUSIIL Phishing URL Dataset (UCI id 967). The model deliberately avoids
path, query, scheme, and page-content features to prevent learning collection
artifacts present in this dataset.

Run from the project root:
    python -m ml.train
"""
from __future__ import annotations

import csv
import io
import json
import math
import os
import pickle
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
import tldextract
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

# Absolute import from project root (run as python -m ml.train)
from ml.feature_extractor import (
    ML_FEATURE_NAMES,
    extract_ml_features,
    features_to_vector,
    hostname_from_url,
)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent.parent  # phishguard/
ML_DIR = BASE_DIR / "ml"
DATASET_ZIP = ML_DIR / "dataset" / "phiusiil.zip"
CSV_NAME_IN_ZIP = "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_OUTPUT = ML_DIR / "model.pkl"
METRICS_OUTPUT = ML_DIR / "metrics.json"

# Offline Public Suffix List snapshot (same config as feature_extractor)
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

PRIMARY_MODEL_NAME = "RandomForest"
MODEL_VERSION = "1.0.0"
DATASET_NAME = "PhiUSIIL (UCI id 967)"


def _registered_domain(url: str) -> str:
    """Extract the registered domain for group splitting (domain-level leakage prevention)."""
    hostname = hostname_from_url(url)
    if not hostname:
        return url
    ext = _EXTRACT(hostname)
    rd = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else hostname
    return rd.lower()


def load_dataset() -> tuple[list[str], list[int]]:
    """Load URLs and labels from the zipped PhiUSIIL dataset."""
    print(f"[1/6] Loading dataset from {DATASET_ZIP} ...")
    if not DATASET_ZIP.exists():
        print(f"ERROR: Dataset not found at {DATASET_ZIP}", file=sys.stderr)
        sys.exit(1)

    urls: list[str] = []
    labels: list[int] = []

    with zipfile.ZipFile(str(DATASET_ZIP), "r") as zf:
        with zf.open(CSV_NAME_IN_ZIP) as raw:
            # Handle BOM (utf-8-sig)
            text = io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace")
            reader = csv.DictReader(text)
            for row in reader:
                url = row.get("URL", "").strip()
                label_str = row.get("label", "").strip()
                if not url or label_str not in ("0", "1"):
                    continue
                urls.append(url)
                labels.append(int(label_str))

    print(f"       Loaded {len(urls):,} samples  (legitimate={labels.count(1):,}, phishing={labels.count(0):,})")
    return urls, labels


def extract_features(urls: list[str]) -> np.ndarray:
    """Extract host-lexical feature vectors for all URLs."""
    print("[2/6] Extracting host-lexical features ...")
    n = len(urls)
    n_features = len(ML_FEATURE_NAMES)
    X = np.zeros((n, n_features), dtype=np.float64)

    report_interval = max(1, n // 20)
    for i, url in enumerate(urls):
        feat_dict = extract_ml_features(url)
        X[i, :] = features_to_vector(feat_dict)
        if (i + 1) % report_interval == 0 or i == n - 1:
            pct = 100.0 * (i + 1) / n
            print(f"       {i + 1:>7,}/{n:,} ({pct:5.1f}%)", end="\r")

    print(f"       Extracted {n_features} features for {n:,} samples.          ")
    return X


def split_by_domain(
    urls: list[str], X: np.ndarray, y: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Split data using GroupShuffleSplit on registered domain to prevent data leakage."""
    print("[3/6] Splitting by registered domain (GroupShuffleSplit) ...")

    groups = np.array([_registered_domain(url) for url in urls])
    unique_domains = len(set(groups))
    print(f"       {unique_domains:,} unique registered domains")

    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    train_domains = set(groups[train_idx])
    test_domains = set(groups[test_idx])
    overlap = train_domains & test_domains
    print(f"       Train: {len(train_idx):,}  Test: {len(test_idx):,}")
    print(f"       Domain overlap: {len(overlap)} (should be 0)")
    return X_train, X_test, y_train, y_test


def build_models() -> dict:
    """Return a dict of model name -> untrained estimator."""
    return {
        "LogisticRegression": LogisticRegression(
            max_iter=1000,
            solver="lbfgs",
            random_state=42,
            n_jobs=-1,
        ),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=20,
            min_samples_leaf=10,
            random_state=42,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            eval_metric="logloss",
            n_jobs=-1,
            verbosity=0,
        ),
    }


def evaluate_model(
    model, X_test: np.ndarray, y_test: np.ndarray
) -> dict:
    """Compute evaluation metrics for a trained model."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]  # prob of class 1 (legitimate)
    # For ROC-AUC we use probability of phishing (class 0) since that is the
    # "positive" detection class from a security perspective; however ROC-AUC
    # is symmetric, so we can use class 1 with the understanding that the AUC
    # value is the same.
    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 6),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 6),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 6),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 6),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 6),
    }


def train_and_evaluate(
    X_train: np.ndarray, y_train: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
) -> dict[str, dict]:
    """Train all candidate models and return their metrics."""
    print("[4/6] Training and evaluating models ...")
    models = build_models()
    results: dict[str, dict] = {}

    for name, model in models.items():
        t0 = time.perf_counter()
        print(f"       Training {name} ...", end=" ", flush=True)
        model.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0
        metrics = evaluate_model(model, X_test, y_test)
        metrics["train_time_seconds"] = round(elapsed, 2)
        results[name] = {"model": model, "metrics": metrics}
        print(
            f"done ({elapsed:.1f}s)  "
            f"acc={metrics['accuracy']:.4f}  f1={metrics['f1']:.4f}  auc={metrics['roc_auc']:.4f}"
        )

    return results


def select_primary(results: dict[str, dict]) -> str:
    """Select the primary model. Prefer RandomForest unless another clearly dominates."""
    best_name = PRIMARY_MODEL_NAME
    best_f1 = results[best_name]["metrics"]["f1"]

    for name, data in results.items():
        if name == best_name:
            continue
        # Another model must beat RF by at least 1.5% on F1 to be selected
        if data["metrics"]["f1"] > best_f1 + 0.015:
            best_name = name
            best_f1 = data["metrics"]["f1"]

    return best_name


def get_feature_importances(model, feature_names: tuple[str, ...]) -> list[dict]:
    """Extract global feature importances from the model."""
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = np.abs(model.coef_[0])
    else:
        return []

    ranked = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    return [{"feature": name, "importance": round(float(imp), 6)} for name, imp in ranked]


def save_model(
    model,
    selected_name: str,
    metrics: dict,
    feature_importances: list[dict],
    dataset_info: dict,
) -> None:
    """Save model artifact to ml/model.pkl."""
    print(f"[5/6] Saving model artifact to {MODEL_OUTPUT} ...")
    artifact = {
        "model": model,
        "feature_names": ML_FEATURE_NAMES,
        "model_name": selected_name,
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": DATASET_NAME,
        "sklearn_version": sklearn.__version__,
        "metrics_summary": metrics,
        "feature_importances": feature_importances,
    }
    with open(str(MODEL_OUTPUT), "wb") as f:
        pickle.dump(artifact, f, protocol=pickle.HIGHEST_PROTOCOL)
    size_mb = MODEL_OUTPUT.stat().st_size / (1024 * 1024)
    print(f"       Saved ({size_mb:.1f} MB)")


def save_metrics(
    all_results: dict[str, dict],
    selected_name: str,
    dataset_info: dict,
    feature_importances: list[dict],
) -> None:
    """Save comprehensive metrics to ml/metrics.json."""
    print(f"[6/6] Saving metrics to {METRICS_OUTPUT} ...")

    models_metrics = {}
    for name, data in all_results.items():
        models_metrics[name] = data["metrics"]

    output = {
        "selected_model": selected_name,
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "feature_set": "host-lexical-v1",
        "feature_names": list(ML_FEATURE_NAMES),
        "feature_count": len(ML_FEATURE_NAMES),
        "feature_importances": feature_importances,
        "dataset": {
            "name": DATASET_NAME,
            "source": "UCI Machine Learning Repository (id 967)",
            "total_samples": dataset_info["total_samples"],
            "legitimate_samples": dataset_info["legitimate_count"],
            "phishing_samples": dataset_info["phishing_count"],
            "train_samples": dataset_info["train_samples"],
            "test_samples": dataset_info["test_samples"],
            "split_method": "GroupShuffleSplit by registered domain (20% test)",
            "split_random_state": 42,
        },
        "models": models_metrics,
        "selected_model_metrics": models_metrics[selected_name],
        "bias_documentation": {
            "known_artifacts": [
                "All legitimate URLs are bare homepages (no path, no query).",
                "All legitimate URLs use HTTPS with www prefix.",
                "All phishing URLs have paths and many use HTTP without www.",
                "Page-content columns reflect pages mostly dead/empty at crawl time for phishing.",
            ],
            "mitigation": (
                "Model uses ONLY 21 host-lexical features computed on the hostname "
                "after stripping a leading www prefix. Path, query, scheme, redirect, "
                "and page-content signals are handled by the rule engine instead. "
                "GroupShuffleSplit on registered domain prevents domain-level data leakage."
            ),
            "feature_source": "ml.feature_extractor.extract_ml_features() on hostname only",
            "residual_risk": (
                "Some host-level patterns (e.g. longer hostnames, more subdomains) may "
                "still partially correlate with collection methodology. Model predictions "
                "are combined with rule-based signals in the risk engine, never used alone."
            ),
        },
    }

    with open(str(METRICS_OUTPUT), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print("       Done.")


def main() -> None:
    print("=" * 60)
    print("PhishGuard ML Training Pipeline")
    print("=" * 60)
    t_start = time.perf_counter()

    # 1. Load dataset
    urls, labels = load_dataset()
    y = np.array(labels, dtype=np.int32)

    # 2. Extract features
    X = extract_features(urls)

    # Sanity: check for NaN/Inf
    bad_mask = ~np.isfinite(X)
    if bad_mask.any():
        n_bad = bad_mask.sum()
        print(f"  WARNING: {n_bad} non-finite values found, replacing with 0.")
        X[bad_mask] = 0.0

    # 3. Split
    X_train, X_test, y_train, y_test = split_by_domain(urls, X, y)

    dataset_info = {
        "total_samples": len(urls),
        "legitimate_count": int((y == 1).sum()),
        "phishing_count": int((y == 0).sum()),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
    }

    # 4. Train & evaluate
    all_results = train_and_evaluate(X_train, y_train, X_test, y_test)

    # 5. Select primary model
    selected_name = select_primary(all_results)
    selected_model = all_results[selected_name]["model"]
    selected_metrics = all_results[selected_name]["metrics"]

    print(f"\n  >> Selected model: {selected_name}")
    print(f"     Accuracy:  {selected_metrics['accuracy']:.4f}")
    print(f"     Precision: {selected_metrics['precision']:.4f}")
    print(f"     Recall:    {selected_metrics['recall']:.4f}")
    print(f"     F1:        {selected_metrics['f1']:.4f}")
    print(f"     ROC-AUC:   {selected_metrics['roc_auc']:.4f}")

    # 6. Feature importances
    feature_importances = get_feature_importances(selected_model, ML_FEATURE_NAMES)
    if feature_importances:
        print("\n  Top 10 features:")
        for fi in feature_importances[:10]:
            print(f"     {fi['feature']:30s}  {fi['importance']:.6f}")

    # 7. Save
    save_model(selected_model, selected_name, selected_metrics, feature_importances, dataset_info)
    save_metrics(all_results, selected_name, dataset_info, feature_importances)

    elapsed = time.perf_counter() - t_start
    print(f"\nTraining complete in {elapsed:.1f}s")
    print("=" * 60)


if __name__ == "__main__":
    main()
