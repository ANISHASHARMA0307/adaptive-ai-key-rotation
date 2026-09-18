# Adaptive AI-Based Risk-Aware Key Rotation Framework

A secure file-storage web app where every uploaded file is encrypted with a
**file-specific ChaCha20-Poly1305 key**, and — instead of rotating keys on a
fixed schedule — a **risk engine** scores each file and triggers **key
rotation** automatically once risk crosses a threshold. Every step
(encryption, risk analysis, rotation, re-encryption) is logged to an
**audit trail** and shown on the dashboard.

## One line summary

> We are developing a risk-aware secure file storage framework where each
> file is encrypted using a file-specific ChaCha20-Poly1305 key, and instead
> of relying only on fixed-time rotation, the system analyses the file's
> security risk and triggers key rotation when the risk crosses a defined
> threshold, while maintaining key versions, re-encryption, and an auditable
> history.

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn app:app --reload
```

Open http://127.0.0.1:8000 — register an account, upload a file, and you'll
land on the file's detail page showing encryption details, live risk
analysis, and rotation controls.

`requirements.txt` installs only the core app (no ML libraries) — the app
runs fully end-to-end on this alone, using the rule-based risk engine.

### Enabling the ML (Random Forest) risk engine

ML dependencies (`numpy`, `scikit-learn`, `joblib`) are kept in a **separate,
optional** file, `requirements-ml.txt`, because `numpy`/`scikit-learn` wheel
support for brand-new Python releases (e.g. 3.14) sometimes lags behind —
installing them can fail with a "metadata-generation-failed" / compiler
error on the very newest Python versions. If that happens to you, either:

- **Use Python 3.11–3.13** for this project (recommended — these have full
  prebuilt-wheel support today), or
- Skip ML entirely — the app works completely fine without it.

To install ML support:

```bash
pip install -r requirements-ml.txt
python -m ai.train_model      # trains and saves ai/model/risk_model.joblib
```

A trained model is already included in this repo
(`ai/model/risk_model.joblib`), so if `requirements-ml.txt` installs
successfully, ML scoring works immediately without retraining.

If `requirements-ml.txt` isn't installed (or the model file is missing),
the app **automatically detects this and falls back** to the deterministic
rule-based engine — nothing crashes, the dashboard just shows "Rule-based
risk engine active" instead of "ML risk engine active".

The SQLite DB (`app.db`) and folders `keys/`, `uploads/`, `encrypted/` are
created automatically on first run.

## How it works

```
Upload File
    -> Encrypt with fresh 256-bit ChaCha20-Poly1305 key (v1)
    -> Risk Analysis (rule-based engine, ai/risk_engine.py)
    -> Risk Score computed from: encryption baseline, file type,
       file age, key age, access/download count
    -> Risk > Threshold (70)?
         NO  -> key stays active, nothing else happens
         YES -> Decrypt with old key
                Generate new key (v_n+1)
                Re-encrypt file with new key
                Old key -> INACTIVE (kept on disk + DB, never deleted)
                New key -> ACTIVE
                Audit log entries written (KEY_ROTATION, RE_ENCRYPTION)
```

Rotation can also be **forced** from the UI for demo/evaluation purposes
without waiting for risk to naturally cross the threshold.

## Project structure

```
AI-Key-Rotation/
├── app.py              FastAPI app + all routes
├── rotation.py          Core adaptive rotation orchestration
├── config.py             Paths, risk weights, threshold
├── database.py           SQLAlchemy engine/session
│
├── crypto/
│   ├── chacha.py          Low-level ChaCha20-Poly1305 (key/nonce/enc/dec)
│   ├── file_crypto.py      File <-> ciphertext-on-disk bridge
│   └── key_manager.py      Key generation, storage, fingerprinting
│
├── auth/auth.py          Password hashing + session-based login
├── models/models.py      User, FileRecord, KeyRecord, AuditLog (SQLAlchemy)
│
├── ai/
│   ├── risk_engine.py      Rule-based engine + engine selection/fallback logic
│   ├── ml_risk_engine.py    ML engine — loads trained Random Forest, predicts risk
│   ├── features.py          Shared feature extraction (training + inference)
│   ├── train_model.py        Generates synthetic data, trains + saves the model
│   └── model/risk_model.joblib  Trained model artifact (included, ready to use)
│
├── logs/audit.py          Central audit-log writer
│
├── keys/                 Per-file, per-version key files (file_<id>_v<n>.key)
├── uploads/                Transient upload staging (cleared after encrypt)
├── encrypted/               Encrypted file blobs
│
├── static/style.css
├── templates/             Jinja2 templates (dashboard, file detail, auth)
└── requirements.txt
```

## Why ChaCha20-Poly1305 instead of AES?

It's a modern AEAD (authenticated encryption) cipher — same security goals
as AES-GCM, but software-friendly (no hardware AES-NI dependency) and a
deliberately different choice from the typical AES/DES college project.
256-bit key, 96-bit nonce, integrity + confidentiality in one pass.

## Risk scoring: ML (Random Forest) with rule-based fallback

`ai/risk_engine.py` exposes a single `.score(file_record, key_record)`
interface. Two engines implement it:

- **`RuleBasedRiskEngine`** (`ai/risk_engine.py`) — deterministic, explainable
  formula:

  | Factor | Contribution |
  |---|---|
  | Encryption baseline | +10 |
  | File type (high/medium/low sensitivity) | +5 to +20 |
  | File age | up to +25 |
  | Key age | up to +30 |
  | Download/access count | up to +15 |

- **`MLRiskEngine`** (`ai/ml_risk_engine.py`) — a **Random Forest
  Regressor** (scikit-learn) trained on features `file_age_days`,
  `key_age_days`, `file_type_risk_level`, `download_count`, `file_size_kb`
  (see `ai/features.py`). It's the **default/active engine** whenever a
  trained model file exists at `ai/model/risk_model.joblib`.

Threshold = **70**. Score above it -> `ROTATION REQUIRED`. This applies
identically regardless of which engine produced the score.

### Training the model

```bash
python -m ai.train_model
```

This generates a synthetic labeled dataset (6,000 samples) using a
domain-knowledge "ground truth" risk function — the same factors as the
rule engine, plus nonlinear interaction terms (e.g. an old key on a
high-sensitivity file compounds risk faster than a plain sum) and gaussian
noise — then trains a `RandomForestRegressor` on it and saves the model to
`ai/model/risk_model.joblib`. On the run in this repo: **MAE ≈ 3.3 risk
points, R² ≈ 0.94** on a held-out test split.

**Why synthetic data:** this is an academic project without months of real
historical incident/audit data to train on. The synthetic labels encode the
same security reasoning a real dataset would need to reflect. The
architecture — features in, model out, swappable engine — is exactly what
would carry over to real historical audit-log data in a production
deployment; only the training data source would change.

### How it shows up in the app

- Dashboard shows a banner: "🧠 ML risk engine active" whenever the model
  is loaded.
- Each file's detail page shows the ML-predicted total score, the same
  named factors as reference input features (labelled as such, since a
  Random Forest doesn't decompose into an additive sum), and a **Model
  Insights** panel with the trained model's feature importances, MAE, and
  R².
- If no trained model is found (`ai/model/risk_model.joblib` missing), the
  app **automatically falls back** to `RuleBasedRiskEngine` so it still
  works end-to-end without ML — nothing crashes, dashboard shows "Rule-based
  risk engine active" instead.

Switching engines, if you ever want to force rule-based even with a trained
model present, is a one-line change in `ai/risk_engine.py`
(`_init_engine()`).

## Security notes (for the demo/viva)

- Raw key bytes are **never** shown in the UI by default — only SHA-256
  **fingerprints**. A `DEMO_MODE_SHOW_KEY_EVIDENCE` flag in `config.py`
  allows showing a truncated key preview for educational evaluation only;
  set it to `False` for anything resembling production use.
- Old keys are **never deleted** on rotation — they're marked `INACTIVE`
  so key history and the audit trail stay intact.
- Passwords are hashed with bcrypt (`passlib`), never stored in plaintext.
- Plaintext uploads are deleted from `uploads/` immediately after
  encryption — only ciphertext persists on disk.

## What's left to build

- Retraining on real historical data once the app has been running long
  enough to accumulate genuine audit-log history (swap `ai/train_model.py`'s
  synthetic `generate_dataset()` for a query against `AuditLog`/`FileRecord`).
- Optional: scheduled/background risk re-analysis (e.g. APScheduler) instead
  of on-demand only.
- Deployment hardening: move `SESSION_SECRET` and any real secrets to
  environment variables, add HTTPS, rate-limit login.
