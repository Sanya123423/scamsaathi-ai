# ScamSaathi: Intelligent Cyber Threat Detection & Risk Assessment System

> **"Think Before You Click. Verify Before You Trust."**  
> *Domain: AI-Based Cybersecurity &bull; Challenge ABSC-01: Intelligent Cyber Threat Detection*

[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9+-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 1. Project Overview

**ScamSaathi** is an intelligent, explainable cybersecurity threat detection and risk assessment system engineered to protect everyday citizens from modern digital fraud. It specializes in analyzing unsolicited SMS, WhatsApp messages, emails, job offers, and suspicious web links across English, Devanagari Hindi, and Hinglish.

Rather than relying on opaque "black box" decisions, ScamSaathi employs a **hybrid detection pipeline** combining deterministic pattern heuristics, safe offline URL forensics, and machine-learning text classification to produce a transparent **0 to 100 Risk Score**, assigned severity ratings (**Low, Medium, High, Critical**), exact matched indicator triggers, and context-specific safety actions.

---

## 2. Key Capabilities & Features

### 🛡️ Multi-Vector Message Threat Analysis
- **Credential & Financial Harvesting**: Detects requests for OTPs, UPI PINs, passwords, CVVs, and NetBanking logins.
- **Advance Fee & Recruitment Fraud**: Identifies fake work-from-home tasks, YouTube-liking scams, and demands for registration deposits.
- **Psychological Coercion & Urgency**: Detects artificial panic deadlines (e.g., "power cutoff tonight by 9:30 PM", "within 2 hours").
- **Authority & Bank Impersonation**: Identifies spoofing of electricity DISCOMs, police/customs agencies, and major banking institutions (SBI, HDFC, ICICI, etc.).
- **Bilingual Detection**: Full native support for English, Hindi in Devanagari script (उदा. *बिजली काट दी जाएगी*, *तुरंत ओटीपी भेजें*), and Romanized Hindi (Hinglish).

### 🔍 Safe Sandbox URL Forensics (100% Zero-Request)
- **Zero-Network Policy**: Inspects URL syntax and domain structures completely offline. Never issues HTTP requests, visits destinations, executes scripts, or downloads files.
- **Deep Structural Heuristics**: Detects raw numerical IP hosts, high-risk disposable TLDs (`.xyz`, `.top`, `.buzz`), URL shortening services (`bit.ly`, `tinyurl`), IDN Punycode homograph attacks (`xn--`), embedded `@` userinfo tricks, and direct APK/executable links.
- **Responsible Disclaimer**: Clean syntax is explicitly labeled as not guaranteeing safety against newly registered malicious servers.

### ⚖️ Explainable Hybrid Risk Scoring
- Combines deterministic rule weights (80%) with auxiliary machine learning features (20%).
- **Single-Keyword Safeguard**: Isolated generic words (e.g., "urgent" or "payment") in normal messages are dampened to Low risk (<25) to prevent false alarms.
- **Compound Signal Detection**: Detects dangerous combinations (e.g., *Urgency + OTP Request* or *Brand Spoofing + Disposable TLD*) and applies risk multipliers.

### 🤖 Machine Learning Text Classifier
- Reproducible pipeline using **TF-IDF vectorization** and **Logistic Regression**.
- Clear separation between statistical predictions and deterministic rule findings.
- Explicit statistical disclaimer: Model confidence reflects training corpus feature alignment, not verified probability of criminality.

### 🔒 Privacy-Conscious Sanitization (Privacy Guard)
- Redacts phone numbers, payment card numbers, PAN identifiers, and OTP tokens before logging or dashboard presentation.

### 📊 Modern Cybersecurity Dashboard
- Dark navy cybersecurity aesthetic with high-contrast, accessible typography.
- Real-time gauge progress meter, dynamic severity badges, and telemetry cards.
- Pre-loaded one-click demo presets for hackathon judges (*Electricity Cutoff Scam*, *Telegram Job Scam*, *Bank KYC Phishing*, *Legitimate Parcel Delivery*).

---

## 3. System Architecture

```text
[ User Input: Suspicious Message and/or URL ]
                    │
                    ▼
     ┌───────────────────────────────┐
     │  Privacy Sanitization Guard   │ ──> Masks phone numbers, card digits & OTPs
     └──────────────┬────────────────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
┌──────────────────┐ ┌──────────────────┐
│ Static URL Engine│ │ Rule Heuristics  │
│ (Zero-request,   │ │ (OTP theft, job  │
│  IP, TLD, Puny)  │ │  scams, urgency) │
└─────────┬────────┘ └────────┬─────────┘
          │                   │
          └─────────┬─────────┘
                    │
                    ▼
     ┌───────────────────────────────┐
     │  TF-IDF + Logistic Regression │ ──> Auxiliary statistical context
     └──────────────┬────────────────┘
                    │
                    ▼
     ┌───────────────────────────────┐
     │ Hybrid Risk Assessment Fusion │ ──> 0 to 100 Score (Low / Medium / High / Critical)
     └──────────────┬────────────────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
┌──────────────────┐ ┌──────────────────────────────────┐
│  SQLite Database │ │ Security Dashboard UI            │
│ (Local telemetry │ │ • Live gauge & severity badges   │
│  & alerts table) │ │ • Detected warning indicators    │
└──────────────────┘ │ • Actionable safety advisories   │
                     │ • One-click demo test presets    │
                     └──────────────────────────────────┘
```

---

## 4. Project Directory Structure

```text
Scam Sathi/
├── app.py                      # Flask backend API server (POST /api/analyze, POST /api/check-url)
├── db.py                       # SQLite telemetry and alert history store
├── requirements.txt            # Project dependencies (Flask, scikit-learn, pandas, joblib)
├── README.md                   # Project documentation and presentation guide
├── .gitignore                  # Excludes virtual environments, caches, and database files
│
├── analyzer/                   # Core cyber threat detection engines
│   ├── __init__.py             # Module exports
│   ├── config.py               # Indicator weights, thresholds, English/Hindi threat patterns
│   ├── privacy.py              # PII redaction (phones, cards, PAN, OTPs)
│   ├── text_analyzer.py        # Context-aware regex matching and compound threat rules
│   ├── url_analyzer.py         # Static offline URL pattern forensics
│   ├── url_checker.py          # Dedicated URL analysis engine (IPs, shorteners, punycode)
│   ├── scoring.py              # Explainable risk scoring & hybrid ML fusion function
│   └── recommendations.py      # Actionable security advisories (e.g. National Helpline 1930)
│
├── ml/                         # Machine learning subsystem
│   ├── __init__.py             # ML exports
│   ├── dataset.py              # Curated seed dataset of legitimate and scam messages
│   ├── train.py                # Reproducible TF-IDF + LogisticRegression training script
│   ├── classifier.py           # Model loader and inference engine
│   ├── scam_classifier.joblib  # Serialized trained model pipeline
│   └── model_meta.json         # Held-out evaluation metrics and dataset limitations
│
├── static/                     # Frontend assets
│   ├── css/
│   │   └── style.css           # Modern dark navy cybersecurity dashboard styles
│   └── js/
│       └── app.js              # Client logic, API integration, telemetry & demo presets
│
├── templates/
│   └── index.html              # Frontend dashboard template
│
└── tests/                      # Automated unit and integration test suite
    ├── test_threat_detection.py # Threat vectors, compound rules & API endpoint tests
    ├── test_url_analyzer.py    # Zero-request URL heuristics & edge case tests
    └── test_ml_classifier.py   # Model loading, predictions, missing inputs & fusion tests
```

---

## 5. Getting Started & Installation

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Modern web browser (Chrome, Edge, Firefox, Brave)

### Local Setup Instructions

```powershell
# 1. Clone or navigate to the project directory
cd "c:\Users\Hp\OneDrive\Desktop\Scam Sathi"

# 2. Create and activate a Python virtual environment (Recommended)
python -m venv venv
.\venv\Scripts\activate       # On Windows
# source venv/bin/activate    # On Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Retrain the Machine Learning Model
python ml/train.py

# 5. Run the automated test suite
python -m unittest discover tests

# 6. Launch the ScamSaathi application
python app.py
```

Open your browser and visit:  
**`http://127.0.0.1:5000`**

---

## 6. Running the Automated Test Suite

ScamSaathi includes comprehensive automated unit and integration tests:

```powershell
python -m unittest discover tests
```

**Test Coverage Summary (32/32 Tests Passing):**
- **Text Threat Detection**: Benign messages, ambiguous single-word dampening, electricity cutoff scams, Telegram jobs, banking OTP credential theft, Hindi/Hinglish language heuristics, and PII masking.
- **Safe Static URL Forensics**: IP hosts, disposable TLDs, URL shorteners, punycode homographs, embedded credentials, dangerous schemes, direct APK links, and malformed inputs.
- **Machine Learning**: Model loading, missing inputs, prediction accuracy, statistical disclaimers, and hybrid fusion weighting.
- **API Endpoints**: `POST /api/analyze`, `POST /api/check-url`, `POST /api/scan`, `GET /api/stats`.

---

## 7. Model Performance & Limitations

### Held-Out Evaluation (25% Test Split)
- **Accuracy**: `80.0%`
- **Precision (Suspicious Class)**: `0.75`
- **Recall (Suspicious Class)**: `0.86`
- **F1-Score**: `0.80`

### Transparent Disclosures
1. **Curated Seed Dataset**: Trained on 60 representative examples across English and Hindi. Real-world commercial deployment requires expanding to tens of thousands of live SMS/email feeds.
2. **Distribution Shift**: Novel zero-day phishing phrasing may diverge from the training distribution; deterministic rule-based heuristics serve as the primary safeguard.
3. **Statistical Confidence**: Model output represents statistical feature alignment with training distributions, **not** an objective mathematical proof of criminal intent.

---

## 8. Emergency Reporting & Cybersecurity Helplines

If you or someone you know has been targeted by a financial cyber fraud:
- **National Cyber Crime Helpline (India)**: Dial **1930** immediately.
- **Official Portal**: Report incidents at [cybercrime.gov.in](https://cybercrime.gov.in).
- **Never share 6-digit OTPs, UPI PINs, or NetBanking passwords with anyone.**

---

## 9. Academic Project Notice
Developed as a B.Tech Computer Science final-year project addressing **Challenge ABSC-01: Intelligent Cyber Threat Detection** in the **AI-Based Cybersecurity** domain.
