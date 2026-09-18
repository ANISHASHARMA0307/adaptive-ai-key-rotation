"""
Trains the Random Forest risk-prediction model.

Why synthetic data: this is a college project without months of real
historical incident data to learn from. So we generate synthetic training
examples using a believable "ground truth" risk function (security-domain
knowledge encoded as a formula, same factors the brief lists: file age,
key age, file type, access frequency, file size) PLUS random noise and a
few nonlinear interaction terms — so the Random Forest has to actually
learn patterns and interactions rather than just memorize a linear sum.

This is a standard, defensible approach for an academic security project:
document that the model is trained on synthetic/simulated risk labels
(clearly disclosed in the README), and the architecture (features -> model
-> prediction, swappable engine) is what would carry over to real
historical audit-log data in a production deployment.

Run:
    python -m ai.train_model
"""

import os
import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score
import joblib

from ai.features import FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "risk_model.joblib")
N_SAMPLES = 6000
RANDOM_SEED = 42


def _ground_truth_risk(file_age_days, key_age_days, file_type_risk_level, download_count, file_size_kb, rng):
    """
    Simulated 'true' risk score used to label synthetic training data.
    Mirrors the rule-based factors from the brief, plus nonlinear
    interaction terms (e.g. an old key on a high-sensitivity file is
    riskier than the sum of its parts) and gaussian noise, so the trees
    have real structure to learn instead of a flat linear function.
    """
    base = 8.0

    age_component = np.minimum(file_age_days * 1.0, 25.0)
    key_age_component = np.minimum(key_age_days * 1.5, 30.0)
    type_component = file_type_risk_level * 10.0  # 0, 10, or 20
    access_component = np.minimum(download_count * 3.0, 15.0)
    size_component = np.minimum(file_size_kb / 500.0, 6.0)

    # nonlinear interaction: old key + sensitive file type compounds risk
    interaction = (key_age_component / 30.0) * (type_component / 20.0) * 12.0

    # nonlinear interaction: frequently accessed + old file compounds exposure
    interaction_2 = (access_component / 15.0) * (age_component / 25.0) * 8.0

    noise = rng.normal(0, 4.0, size=file_age_days.shape)

    total = (
        base + age_component + key_age_component + type_component
        + access_component + size_component + interaction + interaction_2 + noise
    )
    return np.clip(total, 0, 100)


def generate_dataset(n=N_SAMPLES, seed=RANDOM_SEED):
    rng = np.random.default_rng(seed)

    file_age_days = rng.integers(0, 90, size=n).astype(float)
    key_age_days = rng.integers(0, 60, size=n).astype(float)
    file_type_risk_level = rng.choice([0, 1, 2], size=n, p=[0.45, 0.35, 0.20]).astype(float)
    download_count = rng.poisson(2.0, size=n).astype(float)
    file_size_kb = np.abs(rng.normal(800, 900, size=n))

    X = np.column_stack([
        file_age_days, key_age_days, file_type_risk_level, download_count, file_size_kb
    ])
    y = _ground_truth_risk(
        file_age_days, key_age_days, file_type_risk_level, download_count, file_size_kb, rng
    )
    return X, y


def train():
    X, y = generate_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED
    )

    model = RandomForestRegressor(
        n_estimators=200,
        max_depth=10,
        min_samples_leaf=4,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    mae = mean_absolute_error(y_test, preds)
    r2 = r2_score(y_test, preds)

    print(f"Trained RandomForestRegressor on {len(X_train)} samples, tested on {len(X_test)}")
    print(f"  MAE : {mae:.2f} risk points")
    print(f"  R^2 : {r2:.3f}")
    print("Feature importances:")
    for name, imp in sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1]):
        print(f"  {name:24s} {imp:.3f}")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_names": FEATURE_NAMES,
            "trained_on": "synthetic",
            "n_samples": N_SAMPLES,
            "mae": mae,
            "r2": r2,
        },
        MODEL_PATH,
    )
    print(f"Saved model -> {MODEL_PATH}")


if __name__ == "__main__":
    train()
