# 🛡️ AI-Driven Threat Detection & Simulation Engine
### Hack Malenadu '26 · Cybersecurity Track

**Team:** Tejashree D Samant · Vishwa Mehta · Vaibhav K. Madhyastha · Yash Gurnani

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     LAYER 1: INGESTION                          │
│  Kafka-Lite topics: network / endpoint / application            │
│  → Edge Normalization → Unified Event Schema (null-filled)      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ 500+ ev/s
┌──────────────────────────▼──────────────────────────────────────┐
│                   LAYER 2: FEATURE ENGINEERING                  │
│  log(x+1) transform · RobustScaler (IQR) · One-Hot Encoding     │
│  → 40-80 dim feature vector per event                           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌─────────────────┐                ┌──────────────────────┐
│ Isolation Forest│                │  LSTM Autoencoder    │
│ (point anomaly) │                │ (sequence anomaly)   │
└────────┬────────┘                └──────────┬───────────┘
         └──────────────┬──────────────────────┘
                        │ Ensemble (0.6 IF + 0.4 LSTM)
┌───────────────────────▼──────────────────────────────────────┐
│              LAYER 3: XGBOOST CLASSIFICATION                 │
│  Classes: Brute Force | Lateral Movement |                   │
│           Data Exfiltration | C2 Beaconing | Benign          │
│  Severity matrix: confidence + class → CRITICAL/HIGH/MED/LOW │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│           LAYER 4: CROSS-LAYER CORRELATION                   │
│  5-minute window · same src_ip across layers                 │
│  Multi-layer match → confidence boost + severity escalation  │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│           LAYER 5: SHAP EXPLAINABILITY                       │
│  Per-feature SHAP values · Plain-English reasoning           │
│  False Positive filter · Process ancestry mapping            │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│         LAYER 6: DYNAMIC PLAYBOOK GENERATION                 │
│  Context-aware steps · MITRE ATT&CK tagged                   │
│  1-10-60 Rule SLA tracking · Auto-filled IP/user context     │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│              SOC DASHBOARD (React)                           │
│  Live WebSocket feed · SHAP charts · Playbook viewer         │
│  Threat donut · Pipeline phase indicator · Sparklines        │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option A: Docker (Recommended)
```bash
git clone <repo>
cd threat-engine
docker-compose up --build
```
- Dashboard: http://localhost:3000
- API docs:  http://localhost:8000/docs

### Option B: Manual Setup

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## 📁 Project Structure

```
threat-engine/
├── backend/
│   ├── main.py                  # FastAPI app + WebSocket live feed
│   ├── requirements.txt
│   ├── Dockerfile
│   └── pipeline/
│       ├── ingestion.py         # Multi-signal normalization
│       ├── preprocessor.py      # Feature engineering (log, RobustScaler, OHE)
│       ├── detector.py          # Isolation Forest + LSTM Autoencoder ensemble
│       ├── classifier.py        # XGBoost classifier + MITRE mapping
│       ├── correlator.py        # Cross-layer correlation engine
│       ├── explainer.py         # SHAP explainability + plain-English
│       ├── playbook.py          # Dynamic playbook generator
│       └── simulator.py         # Synthetic attack + benign data generator
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Full SOC dashboard
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
├── docker-compose.yml
└── README.md
```

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health |
| GET | `/stats` | Live stats (eps, incidents, FP count) |
| GET | `/incidents` | List incidents (filter by severity) |
| GET | `/incidents/{id}` | Single incident detail |
| POST | `/incidents/{id}/acknowledge` | Acknowledge an incident |
| POST | `/ingest` | Ingest a batch of raw events |
| POST | `/simulate` | Trigger an attack simulation |
| GET | `/playbook/{id}` | Get dynamic playbook for incident |
| WS | `/ws/live-feed` | WebSocket: real-time incident stream |

**Example — Ingest events:**
```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "network",
    "events": [{
      "src_ip": "10.0.1.42",
      "dst_ip": "45.79.23.11",
      "dst_port": 4444,
      "protocol": "TCP",
      "bytes": 312,
      "packets": 5,
      "duration": 1.2
    }]
  }'
```

**Example — Trigger simulation:**
```bash
curl -X POST http://localhost:8000/simulate \
  -H "Content-Type: application/json" \
  -d '{"scenario": "c2_beacon", "intensity": 50, "duration": 10}'
```

---

## 🧠 ML Pipeline Details

### Detection Model
| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Scout | Isolation Forest (contamination=0.01) | Point anomalies: port scans, bulk transfers |
| Sequence | LSTM Autoencoder (MSE threshold) | Temporal anomalies: beaconing, process injection |
| Ensemble | Weighted avg (0.6 IF + 0.4 LSTM) | Combined anomaly_confidence float |

### Classification Model
| Property | Value |
|----------|-------|
| Algorithm | XGBoost (objective: multi:softprob) |
| Training data | CICIDS2018 + synthetic scapy/Python logs |
| Classes | 5 (Benign, Brute Force, Lateral Movement, Data Exfiltration, C2 Beaconing) |
| Features | 40–80 dim (log-transformed + RobustScaled + OHE) |

### Severity Matrix
| Threat | Confidence Threshold | Severity |
|--------|---------------------|----------|
| C2 Beaconing | ≥ 0.85 | CRITICAL |
| Data Exfiltration | ≥ 0.75 | HIGH |
| Lateral Movement | ≥ 0.60 | MEDIUM |
| Brute Force | 0.50–0.70 | MEDIUM |

---

## 🎭 Demo Scenarios

The simulator seeds these simultaneously:

1. **C2 Beaconing** — `10.0.1.42` → `45.79.23.11:4444` every ~60s (CRITICAL)
2. **Brute Force** — External IPs → `/login` endpoint (HIGH)
3. **Lateral Movement** — Internal east-west on port 445 (MEDIUM)
4. **Data Exfiltration** — 100MB+ outbound to external IP (HIGH)
5. **False Positive** — `backup` user running `robocopy.exe` bulk transfer (correctly suppressed ✓)

---

## 🗺️ MITRE ATT&CK Coverage

| Threat | Tactic | Technique |
|--------|--------|-----------|
| Brute Force | Credential Access | T1110 / T1110.001 |
| Lateral Movement | Lateral Movement | T1021 / T1021.002 |
| Data Exfiltration | Exfiltration | T1041 / T1048 |
| C2 Beaconing | Command & Control | T1071 / T1071.001 |

---

## 👥 Team Roles

| Member | Role | Responsibilities |
|--------|------|-----------------|
| Tejashree D Samant | ML Engineer | Isolation Forest, Autoencoder, XGBoost, SHAP |
| Vishwa Mehta | Backend Engineer | Kafka-Lite, FastAPI, normalisation pipeline |
| Vaibhav K. Madhyastha | Frontend Engineer | React SOC dashboard, alert UI, playbook views |
| Yash Gurnani | Data / Security Analyst | CICIDS dataset, MITRE mapping, playbooks |

---

## 🏆 Stretch Goals Implemented

- [x] 3-layer ingestion (network + endpoint + application)
- [x] 4+ threat categories with MITRE ATT&CK mapping
- [x] SHAP plain-English reasoning + false positive indicator
- [x] Dynamically generated context-aware playbooks
- [x] Live SOC-style incident dashboard with WebSocket feed
- [x] Cross-layer correlation engine with confidence boosting
- [x] 1-10-60 Rule SLA tracker
- [x] Threat simulation mode with selectable attack scenarios
