# AI-Driven Threat Detection & Simulation Engine

**Hack Malenadu '26 | Cybersecurity Track**
Team: Tejashree, Vishwa, Vaibhav, Yash

---

## Work Division

| Person | Subsystem | Owns |
|--------|-----------|------|
| **A** | Data & Ingestion | `data_engine/`, `features/` |
| **B** | ML Models (PyTorch) | `models/` |
| **C** | Correlation + Dashboard | `engine/`, `dashboard/` |
| **D** | Simulation + Integration | `simulation/`, `run.py`, `demo_script.md` |

The contract everyone shares: `schema.py` — **do not modify without team consent.**

---

## Hour-by-Hour Plan (36 hours)

### Hours 0–2: Foundation
- **D**: commits this skeleton, sets up GitHub repo with branch protection
- **Everyone**: clone, create `feature/<name>` branch, `pip install -r requirements.txt`
- **A**: start synthetic data generator
- **B**: open Drae, start LSTM architecture
- **C**: write `mitre_mapping.json` + `playbook_templates.yaml`

### Hours 2–8: Core pieces in parallel
- **A**: finish data gen, ingestion, normalizer → **delivers Event stream**
- **B**: Isolation Forest working locally, XGBoost training script ready
- **C**: Streamlit skeleton with fake data, correlation engine draft
- **D**: `run.py` stub with stubs from all three — can it import everything?

### Hour 8: First integration checkpoint
D runs `run.py` with stub data. If imports work and schema flows end-to-end,
you're on track. Fix contracts here, not at hour 24.

### Hours 8–20: Fill in the real logic
- **A**: feature pipeline fitted, saved, loadable
- **B**: LSTM trained on Drae, weights committed; XGBoost trained; SHAP hooked up
- **C**: correlation with PID ancestry; FP suppression; dashboard with real data
- **D**: scenario files built; replayer working

### Hours 20–28: Polish + simulation mode
- **D**: self-validation scorecard, simulation toggle on dashboard
- **C**: 1-10-60 SLA tracker widget; plain-English SHAP translator
- **A/B**: performance — does 500+ ev/sec actually hold?

### Hours 28–34: Demo rehearsal
- **D**: write + rehearse `demo_script.md`
- **Everyone**: run the full demo 3 times end-to-end, fix what breaks

### Hours 34–36: Submission buffer
Videos recorded, slides updated, code frozen. Don't touch anything.

---

## The Golden Rules

1. **Rebase, don't merge.** Keep history linear.
2. **Commit every 2 hours.** Laptop death = 2h loss, not a morning.
3. **D merges to `main`.** Nobody else pushes to main.
4. **Schema changes require team consent.** Breaking `schema.py` breaks everyone.
5. **Standup every 6 hours.** 5 minutes. What / blocked / next.
6. **If you're stuck for >45min, ask.** Pride costs time you don't have.

---

## Quick Start

```bash
git clone <repo>
cd threat-engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Person A: generate demo data
python -m data_engine.simulator

# Person B: train models (LSTM on Colab, others locally)
python -m models.train_all

# Person D: run end-to-end
python run.py

# Person C: launch dashboard
streamlit run dashboard/app.py
```

---

## Known Risks

- **LSTM training time** — if Colab GPU queue is slow, fallback to statistical
  beacon detection (interval variance threshold). Person B decides by hour 12.
- **CICIDS download size** — ~30GB full. Use CICIDS2018 day 1–2 only (~5GB).
- **Streamlit latency with 500+ ev/sec** — don't render every event. Sample,
  or use `st.empty()` placeholders with a refresh budget.
