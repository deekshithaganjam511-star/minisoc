# MiniSOC — Security Operations Center

An AI-powered Security Operations Center simulation that detects, analyzes, and responds to cyber threats using rule-based detection and machine learning.

---

## What It Does

MiniSOC simulates a real SOC environment by:

- Generating realistic attack logs (brute force, credential stuffing, after-hours logins)
- Detecting threats using rule-based logic mapped to MITRE ATT&CK
- Using ML anomaly detection (Isolation Forest) to catch hidden threats
- Generating structured alerts with risk scores and recommended actions
- Visualizing everything in a live Streamlit dashboard
- Auto-generating professional PDF incident reports

---

## Architecture

Log Generator → Rule Engine → ML Detector → Alert Manager → Dashboard → Incident Report

---

## Tech Stack

| Layer            | Technology                      |
| ---------------- | ------------------------------- |
| Language         | Python 3.12                     |
| Machine Learning | scikit-learn (Isolation Forest) |
| Data Processing  | pandas, numpy                   |
| Dashboard        | Streamlit, Plotly               |
| Reporting        | fpdf2                           |
| Log Simulation   | Faker                           |

---

## Project Structure

minisoc/
├── genarate.py # Log generator - simulates attack scenarios
├── rules.py # Rule-based detection engine
├── ml_detector.py # ML anomaly detection (Isolation Forest)
├── alert_system.py # Alert manager with priority scoring
├── app.py # Streamlit SOC dashboard
├── reports.py # PDF incident report generator
├── data/
│ ├── logs.csv # Generated log data
│ ├── rule_alerts.csv # Rule-based alerts
│ ├── ml_results.csv # ML detection results
│ └── final_alerts.csv # Combined final alerts
└── reports/
└── incident_report.pdf

---

## How To Run

### 1. Install dependencies

```bash
pip install pandas numpy scikit-learn streamlit plotly fpdf2 faker
```

### 2. Generate logs

```bash
python genarate.py
```

### 3. Run detection engine

```bash
python rules.py
python ml_detector.py
```

### 4. Generate alerts

```bash
python alert_system.py
```

### 5. Launch dashboard

```bash
python -m streamlit run app.py
```

### 6. Generate incident report

```bash
python reports.py
```

---

## MITRE ATT&CK Coverage

| Technique ID | Technique Name           | Detection Method |
| ------------ | ------------------------ | ---------------- |
| T1110        | Brute Force              | Rule-based + ML  |
| T1110.004    | Credential Stuffing      | Rule-based + ML  |
| T1078        | Valid Accounts           | Rule-based       |
| T1133        | External Remote Services | Rule-based       |

---

## Dashboard Features

- Live alert feed with severity filtering
- Attack timeline chart
- Top targeted users and attacking IPs
- MITRE ATT&CK techniques visualization
- ML risk score distribution
- KPI metrics (total alerts, critical count, ML anomalies)

---

## ML Model Details

- **Algorithm:** Isolation Forest (unsupervised anomaly detection)
- **Features:** login hour, attempt count, user, country, status
- **Contamination rate:** 15%
- **Output:** anomaly score + 0-100 risk score per log entry

---

## Key Concepts Demonstrated

- SOC analyst workflow automation
- SIEM-style log analysis
- SOAR-style automated response
- MITRE ATT&CK framework mapping
- ML-based anomaly detection
- Incident report generation

---

## Author

**Deekshitha** — Cybersecurity Enthusiast

- GitHub: [@deekshithaganjam511-star](https://github.com/deekshithaganjam511-star)
