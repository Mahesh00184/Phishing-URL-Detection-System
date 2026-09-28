# Phishing URL Detection System
**Academic Cybersecurity & Machine Learning Web Application (B.Sc. Final-Year Project)**

![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%2010-blue.svg)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?logo=python)
![Framework](https://img.shields.io/badge/Backend-Flask-black.svg?logo=flask)
![ML](https://img.shields.io/badge/Machine%20Learning-Random%20Forest-green.svg)
![Database](https://img.shields.io/badge/Database-SQLite3-003B57.svg?logo=sqlite)
![Status](https://img.shields.io/badge/Status-Complete%20%26%20Tested-success.svg)

---

## 1. Project Overview & Problem Statement

Phishing is one of the most pervasive cyber threat vectors worldwide, responsible for credential theft, corporate espionage, and financial fraud. Attackers craft fraudulent uniform resource locators (URLs) that visually masquerade as legitimate financial or corporate portals (e.g., banks, Microsoft, Google, PayPal).

Traditional defenses rely heavily on **reactive blacklists** (e.g., Google Safe Browsing, PhishTank). While effective against established campaigns, blacklists suffer from critical delays: new phishing links remain undetected during the first several hours of life (the *zero-hour window*).

This project implements a **proactive, machine-learning-driven Phishing URL Detection System** that analyzes lexical and structural URL markers entirely in memory:
- **100% Local Execution on Windows**: Zero external paid APIs or cloud dependencies required.
- **Safe Static Lexical Inspection**: The target URL is **never opened or downloaded**, preventing exploit kit execution and protecting the investigator.
- **Hybrid Scoring Engine**: Integrates an ensemble **Random Forest Classifier** with rule-based heuristic penalty weights to output a calibrated **0–100 Risk Score**.

---

## 2. Key Objectives & Features

1. **Dashboard (`/`)**:
   - Real-time cybersecurity telemetry loaded dynamically from SQLite.
   - Metrics: Total Scans, Phishing Detected, Likely Safe, High/Medium/Low Risk.
   - Chart.js visualizations: Safe vs. Phishing ratio (doughnut) and risk severity distribution (bar).
   - Quick URL scan input and fast scenario test chips.
   - Recent Scans audit table.
2. **URL Threat Analyzer (`/analyze`)**:
   - Deep lexical decomposition across 18 cybersecurity dimensions.
   - Visual risk gauge (0–100) and risk level status (`LOW`, `MEDIUM`, `HIGH`).
   - Human-readable detection reasons (e.g., raw IP address, suspicious TLD, excessive subdomains).
   - Tailored security recommendations for users and incident response teams.
3. **Persistent Scan History (`/history`)**:
   - Stores all analyses in local SQLite (`database/scans.db`).
   - Live URL/domain search and status filtering (Phishing, Safe, High/Med/Low).
   - Single-record deletion and full database purge modal with confirmation.
4. **Academic Cybersecurity Documentation (`/about`)**:
   - In-depth educational review of phishing anatomy, URI RFC standards, ML model mathematics, and defense-in-depth principles.

---

## 3. System Architecture

```
User Input (Web Browser)
        │
        ▼
Flask Application Controller (app.py)
        │
   ┌────┴─────────────────────────────┐
   ▼                                  ▼
URL Normalization & Validation    Lexical Feature Extractor (18 Metrics)
(Safe against SSRF/Injection)     (Zero Network Traversal)
                                      │
   ┌──────────────────────────────────┤
   ▼                                  ▼
Random Forest Classifier          Heuristic Threat Engine
(models/phishing_model.pkl)       (IP, @, Shorteners, TLDs)
   │                                  │
   └───────────────┬──────────────────┘
                   ▼
       Calibrated Risk Score (0–100)
       [LOW: 0–30 | MEDIUM: 31–70 | HIGH: 71–100]
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
SQLite Database (scans.db)  Forensic UI Render (Jinja2 + Chart.js)
```

---

## 4. Extracted Cybersecurity Features (18 Metrics)

| # | Feature Name | Category | Cybersecurity Threat Significance |
|---|---|---|---|
| 1 | `url_length` | Structural | Long URLs often disguise malicious parameters and payload tokens. |
| 2 | `domain_length` | Structural | Spoofed domains frequently include lengthy brand names to deceive victims. |
| 3 | `num_dots` | Lexical | Excessive dots indicate nested subdomains masking the authoritative root domain. |
| 4 | `num_hyphens` | Lexical | Hyphens are widely used in typosquatting lures (e.g., `paypal-security-check.com`). |
| 5 | `num_special_chars` | Lexical | Unusually high count of `@ ? = & % _ ~` flags obfuscation or complex tracking queries. |
| 6 | `num_digits` | Lexical | Dense numeric tokens often indicate algorithmic domain generation (DGAs). |
| 7 | `num_subdomains` | Structural | More than 2 subdomains typically indicates brand spoofing on dynamic DNS. |
| 8 | `has_ip_address` | Host Type | Raw IPv4/IPv6 addresses bypass domain registration records and standard DNS filters. |
| 9 | `has_at_symbol` | Lexical | Everything preceding `@` is parsed as userinfo, redirecting users to an unexpected host. |
| 10 | `suspicious_word_count` | Semantic | Frequency of words like `login, verify, secure, banking, update, confirm, password`. |
| 11 | `has_https` | Protocol | While phishing can use free SSL, HTTP credential requests remain an immediate alert. |
| 12 | `num_params` | Structural | High parameter counts are common in victim-tracking phishing kits. |
| 13 | `path_length` | Structural | Elaborate nested directory paths are generated by automated phishing toolkits. |
| 14 | `domain_age_heuristic` | Reputation | Local heuristic evaluating established top domains vs. unrated new domains. |
| 15 | `is_shortened` | Anonymity | Shortening services (`bit.ly`, `tinyurl.com`) hide destination targets. |
| 16 | `suspicious_tld` | Reputation | Abused TLDs (`.tk`, `.ml`, `.xyz`, `.top`, `.work`, etc.) with cheap registration. |
| 17 | `digit_ratio` | Statistical | Ratio of numeric digits to total characters; high values signal DGAs. |
| 18 | `entropy` | Information Theory | Shannon Entropy calculation detecting randomized, encoded, or obfuscated tokens. |

---

## 5. Machine Learning Pipeline

- **Algorithm**: `RandomForestClassifier` (100 Decision Trees, `max_depth=14`)
- **Dataset**: `dataset/phishing_urls.csv` (Curated balance of legitimate and malicious URLs)
- **Train/Test Split**: 80% Training, 20% Testing (Stratified)
- **Artifacts**: Saved to `models/phishing_model.pkl` and `models/model_metadata.json`
- **Scoring Formula**:
  $$\text{Risk Score} = 0.70 \times (P_{\text{phish}} \times 100) + 0.30 \times \min(\text{Heuristic Penalties}, 100)$$

---

## 6. Windows Setup & Local Execution Instructions

Follow these steps in **Windows PowerShell**:

### Step 1: Open the Project Directory
```powershell
cd Phishing-URL-Detection-System
```

### Step 2: Create a Python Virtual Environment
```powershell
python -m venv venv
```

### Step 3: Activate the Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Start the Flask Application
```powershell
python app.py
```

### Step 6: Open in Your Web Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Cloud Production Deployment (Render)

This application is production-ready for deployment on **Render** (or any WSGI-compatible cloud platform):

- **Platform**: Render Web Service
- **Runtime**: Python 3.11+
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn app:app`
- **Port Handling**: Configured to dynamically bind to the platform `$PORT` environment variable.
- **Security**: In production, `FLASK_DEBUG` defaults to `false` and `SECRET_KEY` can be provided via environment variables.

### SQLite Cloud Persistence Limitation Note
> **Important**: Cloud container platforms (such as Render's free tier) utilize an **ephemeral filesystem**. Any records stored in SQLite (`database/scans.db`) will reset when the instance restarts or redeploys unless a persistent disk is attached. For production systems requiring permanent historical audit retention across container restarts, mount a persistent volume or connect an external managed database (e.g., PostgreSQL).

---

## 8. Project Structure

```
Phishing-URL-Detection-System/
│
├── app.py                     # Main Flask web application & REST routes
├── train_model.py             # Random Forest training and evaluation pipeline
├── test_system.py             # Automated test suite (routes, features, ML, DB)
├── requirements.txt           # Python dependencies (Flask, scikit-learn, joblib, gunicorn)
├── Procfile                   # Cloud process manager configuration (gunicorn app:app)
├── render.yaml                # Render Blueprint deployment definition
├── .python-version            # Python version specification (3.11.9)
├── README.md                  # Comprehensive academic & deployment documentation
│
├── dataset/
│   └── phishing_urls.csv      # Balanced URL training corpus
│
├── models/
│   ├── phishing_model.pkl     # Serialized trained Random Forest classifier
│   └── model_metadata.json    # Model evaluation metrics and feature importances
│
├── database/
│   ├── db.py                  # SQLite database queries and analytics helper
│   └── scans.db               # SQLite database file storing scan audit logs
│
├── utils/
│   ├── __init__.py            # Feature extractor exports
│   └── url_features.py        # 18 lexical/structural cybersecurity features & entropy
│
├── templates/
│   ├── base.html              # Cyber-themed master template with navigation
│   ├── index.html             # Real-time dashboard with Chart.js analytics
│   ├── analyze.html           # Deep URL threat analyzer with risk gauge & reasons
│   └── history.html           # Forensic scan history with search & deletion
│
└── static/
    ├── css/
    │   └── style.css          # Glassmorphic cybersecurity dark theme
    ├── js/
    │   └── script.js          # Chart.js initialization & dynamic interactions
    └── images/                # Asset storage
```

---

## 8. Security & Ethical Considerations

1. **Passive Threat Hunting**: The system does not transmit HTTP/S GET or POST requests to analyzed links.
2. **Defensive Validation**: Strict input sanitization prevents Cross-Site Scripting (XSS), SQL Injection, and Server-Side Request Forgery (SSRF).
3. **No False Guarantees**: Clean URLs are classified as *"Likely Safe"* rather than 100% immune, maintaining defense-in-depth integrity.

---

## 9. Academic Credit & Presentation Notes

- **Degree**: Bachelor of Science in Computer Science (B.Sc. CS)
- **Domain**: Cybersecurity / Applied Artificial Intelligence
- **Evaluation Criteria Met**:
  - Independent offline execution on Windows.
  - Multi-feature extraction adhering to URI RFC standards.
  - Supervised learning with confusion matrix and Gini importance ranking.
  - Relational persistence in SQLite with full CRUD and aggregation.
  - Professional SOC/cybersecurity dashboard user interface.
