# BASTION IDS

**B**ehavioral **A**nalysis **S**ecurity **T**hreat **I**ntelligence & **O**perations **N**etwork

A production-grade, ML-powered Intrusion Detection System with a full Security Operations Center (SOC) web interface. Built with Flask, XGBoost, and the CIC-IDS2017 dataset.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?logo=flask)
![XGBoost](https://img.shields.io/badge/XGBoost-2.1-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

### Threat Detection
- **Ensemble ML Classification** — Random Forest + XGBoost + MLP Neural Network with soft-voting ensemble and per-class threshold tuning (99.9% accuracy)
- **15 Attack Classes** — DDoS, DoS (Hulk, GoldenEye, Slowloris, Slowhttptest), PortScan, Brute Force (FTP, SSH, Web), SQL Injection, XSS, Infiltration, Heartbleed, Bot
- **Real-time Streaming** — Server-Sent Events (SSE) for live scan progress with pause/resume/restart controls
- **PCAP & CSV Support** — Upload network flow CSVs or raw PCAP files for analysis
- **SHAP Explainability** — Per-flow feature importance using SHAP values

### SOC Dashboard
- **Live KPI Cards** — Total scans, flows, threats, and unread alerts with real-time SSE updates
- **Threat Timeline** — Chronological attack visualization with severity color coding
- **Heatmap Analysis** — Day-of-week vs hour-of-day attack pattern heatmap
- **3D Globe Map** — Geographic threat visualization using Globe.gl
- **Geolocation Maps** — Leaflet-based IP mapping with abuse score overlays

### Threat Intelligence
- **AbuseIPDB Integration** — IP reputation scoring with 24-hour cache
- **VirusTotal Enrichment** — Multi-engine malware detection results
- **Shodan Intelligence** — Open port and CVE enumeration
- **WHOIS Lookup** — Domain and IP ownership information
- **IP Watchlist** — Monitor suspicious IPs with expiration and alert triggers

### Case Management
- **Multi-tier Workflow** — Analyst -> CC Admin -> Admin escalation path
- **SLA Tracking** — Overdue/Warning/On-Track status indicators
- **File Attachments** — Upload evidence (PDF, PCAP, images, Office docs, ZIP)
- **Investigation Notes** — Timestamped comments with user attribution
- **Auto-archiving** — Closed cases archived by year/month
- **PDF Export** — Generate case summary reports

### Incident Response
- **Attack Playbooks** — MITRE ATT&CK-mapped response procedures per attack type
- **Threat Hunting** — Multi-field search across all historical scan data
- **Attack Correlation** — Source IP threat scoring (Flow Count x Severity Rank)
- **Network Topology** — D3.js force-directed IP relationship graphs
- **Scan Comparison** — Side-by-side metrics for 2-5 scans

### Administration
- **Role-Based Access Control** — Admin, CC Admin (Compliance), Analyst roles
- **Two-Factor Authentication** — TOTP-based 2FA with QR code enrollment
- **hCaptcha Protection** — Bot prevention on login
- **Complete Audit Trail** — Every user action logged with timestamp
- **SMTP Email Alerts** — Configurable email notifications for critical/high severity
- **Slack Webhook Integration** — Real-time Slack channel alerts
- **User Management** — Create, disable, promote, assign analysts to CC Admins

### Internationalization
- **Bilingual** — Full English and Arabic support (1140+ translated strings)
- **RTL Layout** — Right-to-left CSS support for Arabic
- **Arabic Font** — Noto Naskh Arabic font family included

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Flask 3, Python 3.10+ |
| **ML Models** | XGBoost, Random Forest, MLP (scikit-learn), SHAP |
| **Dataset** | CIC-IDS2017 (Canadian Institute for Cybersecurity) |
| **Frontend** | Jinja2, CSS3 (dark cyberpunk theme), vanilla JS |
| **Charts** | Chart.js, D3.js v7 |
| **Maps** | Leaflet, Globe.gl |
| **Icons** | Lucide |
| **Security** | SHA-256 password hashing, CSRF protection, TOTP 2FA, hCaptcha |
| **Exports** | PDF (fpdf2), CSV, CEF (SIEM) |

---

## Quick Start

### Prerequisites
- Python 3.10 or higher
- 8 GB RAM minimum (models are large)

### 1. Clone the Repository
```bash
git clone https://github.com/aliholmes5544/BASTION-IDS.git
cd BASTION-IDS
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Prepare Data & Models

#### Training (optional — only if you want to retrain)
Download the [CIC-IDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) and place CSV files in `data/`:
```
data/
  Monday-WorkingHours.pcap_ISCX.csv
  Tuesday-WorkingHours.pcap_ISCX.csv
  Wednesday-workingHours.pcap_ISCX.csv
  Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
  Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
  Friday-WorkingHours-Morning.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

Run the training pipeline:
```bash
python main.py
```

This produces model files in `models/` (~6.8 GB total).

#### Pre-trained Models (recommended)
Download the pre-trained models from Google Drive and place them in the `models/` folder:

**[Download Models (6.8 GB)](https://drive.google.com/drive/folders/1BD7zoirn0I9FBzOLS6StNz8BPSLpSCgN?usp=sharing)**

```
models/
  best_model.pkl          # ThresholdClassifier (primary — required)
  preprocessor.pkl        # StandardScaler pipeline (required)
  label_encoder.pkl       # Attack class labels (required)
  feature_names.pkl       # Selected feature names (required)
  xgb_model.pkl           # XGBoost standalone
  rf_model.pkl            # Random Forest standalone
  mlp_model.pkl           # MLP Neural Network standalone
  ensemble_model.pkl      # Voting Classifier
  tuned_model.pkl         # Threshold-tuned ensemble
```

> **Minimum required:** `best_model.pkl`, `preprocessor.pkl`, `label_encoder.pkl`, `feature_names.pkl`

### 4. Run the Application
```bash
python app.py
```

Open [http://localhost:5001](http://localhost:5001) in your browser.

### 5. Login
Default admin credentials:
- **Username:** `admin`
- **Password:** `admin`

> Change the default password immediately after first login via Settings > Change Password.

---

## Project Structure

```
BASTION IDS/
├── app.py                  # Flask application (112 routes)
├── main.py                 # ML training pipeline
├── config.json             # Configuration (users, API keys, SMTP)
├── requirements.txt        # Python dependencies
├── models/                 # Trained ML models (not in git)
├── data/                   # CIC-IDS2017 CSV files (not in git)
├── outputs/                # Runtime data (scan history, cases, audit)
├── templates/              # 41 Jinja2 HTML templates
│   ├── base.html           # Master layout with sidebar navigation
│   ├── dashboard.html      # Main SOC dashboard
│   ├── scan.html           # File upload & scan interface
│   ├── result.html         # Scan results with threat breakdown
│   ├── cases.html          # Case management
│   ├── threat_intel.html   # Threat intelligence feed
│   └── ...                 # 35 more templates
├── static/
│   ├── css/bastion.css     # Dark cyberpunk theme (2600+ lines)
│   ├── js/bastion.js       # Core JavaScript (1280+ lines)
│   ├── vendor/             # Chart.js, D3.js, Leaflet, Globe.gl, Lucide
│   └── fonts/              # Noto Naskh Arabic
└── .gitignore
```

---

## ML Training Pipeline

The training pipeline (`main.py`) performs an 11-step process:

1. **Data Loading** — Concatenate all CIC-IDS2017 CSV files
2. **Data Cleaning** — Remove missing labels, drop duplicates, median imputation
3. **Label Encoding** — Encode 15 attack classes
4. **Stratified Split** — 70% train / 15% validation / 15% test
5. **Feature Selection** — Top 70 features via Random Forest Gini importance
6. **Preprocessing** — StandardScaler normalization
7. **SMOTE Resampling** — 3-stage class imbalance handling
8. **Model Training** — Random Forest (600 trees), XGBoost (700 estimators), MLP (512-256-128-64)
9. **Ensemble** — Soft-voting RF+XGB (weights 1:3)
10. **Threshold Tuning** — Per-class scale factor optimization on validation set
11. **Evaluation** — Macro F1, Weighted F1, Accuracy, ROC-AUC

### Model Performance
| Metric | Score |
|--------|-------|
| Accuracy | 99.9% |
| Macro F1 | 89.9% |
| ROC-AUC | 100.0% |

---

## Configuration

### API Keys (Settings page)
- **AbuseIPDB** — IP reputation scoring ([get key](https://www.abuseipdb.com/account/api))
- **VirusTotal** — Malware detection ([get key](https://www.virustotal.com/gui/my-apikey))
- **Shodan** — Host intelligence ([get key](https://account.shodan.io/))

### Email Alerts
Configure SMTP settings in the Settings page for email notifications on critical/high severity detections.

### Slack Alerts
Add a Slack webhook URL in Settings for real-time channel notifications.

### Environment Variables (optional)
```bash
export SECRET_KEY="your-random-secret-key-here"
export BASTION_DATA_DIR="/path/to/custom/data"
```

---

## User Roles

| Role | Permissions |
|------|------------|
| **Admin** | Full access — user management, settings, all features |
| **CC Admin** | Compliance oversight — case review, analyst management |
| **Analyst** | Operational — scan, triage, investigate, create cases |

---

## Screenshots

The BASTION IDS features a dark cyberpunk-themed SOC interface with:
- Glassmorphism card design with neon cyan/purple accents
- Animated particle background
- Responsive layout with collapsible sidebar
- Real-time threat gauges and severity badges

---

## Security Features

- SHA-256 password hashing
- CSRF token protection on all forms and AJAX calls
- TOTP two-factor authentication
- hCaptcha bot protection on login
- Session timeout (120 min idle)
- Security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- Rate limiting on login and 2FA attempts
- CSV export sanitization (formula injection prevention)
- Role-based access control on all routes

---

## License

This project is developed for educational and research purposes.

---

## Acknowledgments

- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — Canadian Institute for Cybersecurity
- [MITRE ATT&CK](https://attack.mitre.org/) — Threat classification framework
- [Chart.js](https://www.chartjs.org/), [D3.js](https://d3js.org/), [Leaflet](https://leafletjs.com/), [Globe.gl](https://globe.gl/) — Visualization libraries
