# Adaptive AI-Based Risk-Aware Key Rotation Framework

[![Live Demo](https://img.shields.io/badge/Render-Live%20Demo-46E3B7.svg?style=for-the-badge&logo=render&logoColor=white)](https://adaptive-ai-key-rotation.onrender.com)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)
![Encryption](https://img.shields.io/badge/Cipher-ChaCha20--Poly1305-blueviolet.svg?style=for-the-badge&logo=letsencrypt&logoColor=white)
![ML Model](https://img.shields.io/badge/Model-Random%20Forest%20Regressor-brightgreen.svg?style=for-the-badge&logo=scikit-learn&logoColor=white)

An enterprise-grade, intelligent cryptographic file storage framework inspired by **Google Drive / Google Workspace**. Traditional systems rotate encryption keys on rigid calendar schedules (e.g., every 30–90 days). This framework continuously computes multi-factor exposure risk using an integrated **Random Forest Machine Learning model** and orchestrates **automatic key rotation and file re-encryption** dynamically the moment risk exceeds defined security thresholds.

---

## 🌐 Live Cloud Deployment

The application is deployed live on Render:

🔗 **[https://adaptive-ai-key-rotation.onrender.com](https://adaptive-ai-key-rotation.onrender.com)**

*(Note: Free tier instances on Render automatically spin down during inactivity and take ~30 seconds to wake up on initial request).*

---

## 🎯 Key Highlights

*   **Google Drive UI/UX Design System**: Complete Google Workspace visual experience—top navigation bar, center Omni search bar with real-time filtering, left sidebar with authentic Material "+ New Upload" floating action button (FAB), and color-coded file icons.
*   **Adaptive Key Rotation**: Keys rotate autonomously when threat conditions demand it, optimizing both security and computational overhead.
*   **Modern Authenticated Encryption**: Implements **ChaCha20-Poly1305 AEAD** (256-bit key, 96-bit nonce) offering robust integrity and confidentiality.
*   **Predictive Risk Modeling**: Evaluates file type sensitivity, data volume exposure, file age, and key aging using a trained Random Forest ML Engine (trained on 6,000 samples; MAE ≈ 3.3, R² ≈ 0.94).
*   **Continuous Dynamic Age & Exposure Metrics**: Measures payload size (+3 to +10 data exposure) and dynamic age progression continuously in hours and days (starting at active baseline +0.5).
*   **Autonomous Monitoring**: Built-in APScheduler constantly surveys assets in the background, executing seamless rotations without manual intervention.
*   **State-Machine Rotation Control**: Enforces single-rotation transitions ($v_1 \rightarrow v_2$) for sustained threats, eliminating infinite re-encryption loops.
*   **Active Post-Rotation Mitigation**: Automatically recalculates risk with fresh active keys, instantly reducing the risk score (e.g., from 43 to 27 / LOW) upon mitigation.
*   **Zero-Exposure Cryptographic Hygiene**: Secret key bytes and hex strings are never displayed on the UI or written to audit logs; keys are tracked strictly via truncated SHA-256 fingerprints.

---

## 🚀 Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/ANISHASHARMA0307/adaptive-ai-key-rotation.git
cd adaptive-ai-key-rotation

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate      # Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Application
```bash
python app.py
```

### 3. Access Dashboard
Open **[http://localhost:8000](http://localhost:8000)** (or `http://127.0.0.1:8000`) in your browser:
*   Register an account or log in.
*   The ML engine initializes automatically on boot—no separate training or worker processes are required.

---

## ⚙️ System Architecture & Execution Flow

```mermaid
graph TD
    A[Upload File .zip, .pdf, etc.] --> B[Encrypt with ChaCha20-Poly1305 Key v1 ACTIVE]
    B --> C{Random Forest ML Risk Assessment}
    
    C -->|Risk ≤ 30 LOW| D[Safe Range: Key v1 remains ACTIVE]
    C -->|Risk > 30 MEDIUM / HIGH| E[Background Scheduler Triggered]
    
    E --> F[Decrypt with v1 Key]
    F --> G[Generate Key v2 256-bit]
    G --> H[Re-encrypt File Blob]
    H --> I[v1 ➔ INACTIVE | v2 ➔ ACTIVE]
    I --> J[Fresh Post-Rotation ML Analysis]
    J --> K[Audit Logs Recorded Fingerprints only]
    K --> L[Live UI Updates Automatically]
```

---

## 📊 Risk Scoring & Mitigation Model

Risk is evaluated on a **0–100 scale** with a **Threshold of 30**:

| Score Tier | Level | Action Taken |
|---|---|---|
| **0 – 30** | 🟢 `LOW` | **Safe**: Key remains active; monitoring continues. |
| **31 – 60** | 🟡 `MEDIUM` | **Rotation Required**: Background scheduler automatically rotates active key. |
| **61 – 80** | 🟠 `HIGH` | **High Threat**: Rapid rotation + mitigation logging. |
| **81 – 100** | 🔴 `CRITICAL` | **Severe Threat**: Immediate priority rotation & review. |

### Contributing Factors
*   **Intrinsic Sensitivity**: Extension categorization (e.g., high-exposure `.zip`, `.exe`, `.sql` vs standard `.pdf`, `.docx`).
*   **Data Volume Exposure**: Larger file sizes carry higher inherent exposure risks.
*   **File Age**: Stagnant files accumulate dormant risk over time.
*   **Cryptographic Key Age**: Aging keys compound exposure and cryptographic vulnerability over time.
*   **Rotation Mitigation**: Active cryptographic mitigation grants **-15 risk credit** upon key renewal, securely returning scores to the safe band.

---

## 🧪 Verification & Testing Guide

### Test 1: Low-Risk File (PDF)
1. Upload a standard `.pdf` document.
2. Initial ML score produces $\approx \mathbf{29.7}$ (`LOW`).
3. Key remains **`v1 ACTIVE`**; scheduler cycles confirm no rotation occurs.

### Test 2: High-Risk Automatic Rotation (ZIP)
1. Upload a `.zip` archive.
2. ML predicts $\approx \mathbf{42.0}$ (`MEDIUM` $\rightarrow$ **ROTATION REQUIRED**).
3. Without refreshing or clicking buttons, wait **15–30 seconds**.
4. The background scheduler rotates key:
   *   `v1` $\rightarrow$ `INACTIVE`
   *   `v2` $\rightarrow$ `ACTIVE`
   *   Risk score automatically updates to $\approx \mathbf{27.0}$ (`LOW`).
   *   Audit trail registers `KEY_ROTATION` and `RE_ENCRYPTION`.
5. Subsequent cycles keep `v2` steady without infinite rotation loops.

---

## 📁 Project Directory Layout

```text
adaptive-ai-key-rotation/
├── app.py                     # FastAPI application, auth, file routes & API
├── rotation.py                # State-machine rotation orchestration & monitoring
├── config.py                  # Cryptographic & scheduler configurations
├── database.py                # SQLAlchemy session manager (SQLite / PostgreSQL)
├── requirements.txt           # Production & ML dependencies
├── render.yaml                # Render Blueprint configuration for 1-click cloud deployment
├── Procfile                   # Cloud process manager start command
│
├── ai/
│   ├── risk_engine.py         # Unified risk scoring interface & baseline engine
│   ├── ml_risk_engine.py      # Random Forest ML model loader & feature evaluator
│   ├── features.py            # Feature vector extractor (train & inference parity)
│   ├── train_model.py         # Random Forest training script (6,000 synthetic samples)
│   └── model/
│       └── risk_model.joblib  # Pre-trained Random Forest model artifact
│
├── crypto/
│   ├── chacha.py              # Low-level ChaCha20-Poly1305 encryption primitives
│   ├── file_crypto.py         # File read/write/re-encryption handler
│   └── key_manager.py         # 256-bit key generator & SHA-256 fingerprinting
│
├── models/
│   └── models.py              # User, FileRecord, KeyRecord, and AuditLog schemas
├── logs/
│   └── audit.py               # Cryptographically sanitized security event logger
│
├── templates/                 # Jinja2 HTML templates (Dashboard, File Detail, Auth)
└── static/                    # Responsive CSS stylesheet
```

---

## 🔒 Security & Compliance Considerations

*   **Fingerprints Only**: Keys are identified in the UI and database exclusively by their truncated SHA-256 fingerprint (e.g., `7A8087A1998F...`).
*   **Immutable Key History**: Prior keys are never deleted; they are preserved as `INACTIVE` to ensure forensic auditability and historical decryption verification.
*   **Ephemeral Plaintext**: Uploaded plaintext files are unlinked from disk immediately following encryption; only ciphertext blobs persist.
*   **Bcrypt Password Storage**: Passwords are cryptographically salted and hashed using `passlib[bcrypt]`.
