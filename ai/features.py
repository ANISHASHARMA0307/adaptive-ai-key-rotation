"""
Shared feature engineering for the ML risk model. Both training
(train_model.py) and inference (ml_risk_engine.py) import this so the
feature vector is guaranteed to match — a very common bug source in
student ML projects is training/inference feature skew, so we centralize
it here.

Features (in fixed order):
    0. file_age_days        - how long since the file was uploaded
    1. key_age_days         - how long the active key has been in use
    2. file_type_risk_level - 0 = low, 1 = medium, 2 = high sensitivity extension
    3. download_count       - how many times the file has been decrypted/downloaded
    4. file_size_kb          - file size in KB (larger sensitive files -> slightly higher exposure)
"""

FEATURE_NAMES = [
    "file_age_days",
    "key_age_days",
    "file_type_risk_level",
    "download_count",
    "file_size_kb",
]

HIGH_RISK_EXTENSIONS = {"exe", "zip", "sql", "env", "pem", "key", "bak", "db"}
MEDIUM_RISK_EXTENSIONS = {"docx", "xlsx", "pdf", "pptx", "csv"}


def file_type_risk_level(file_type: str) -> int:
    ext = (file_type or "").lower().lstrip(".")
    if ext in HIGH_RISK_EXTENSIONS:
        return 2
    if ext in MEDIUM_RISK_EXTENSIONS:
        return 1
    return 0


def build_feature_vector(file_age_days, key_age_days, file_type, download_count, file_size_kb):
    """Return the feature list in the exact order the model expects."""
    return [
        float(file_age_days),
        float(key_age_days),
        float(file_type_risk_level(file_type)),
        float(download_count),
        float(file_size_kb),
    ]
