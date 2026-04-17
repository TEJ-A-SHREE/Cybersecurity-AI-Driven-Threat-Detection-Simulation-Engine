# Review Quick Reference

## One-line elevator pitch
AI-driven threat detection engine that ingests multi-layer telemetry, detects and
classifies threats with explainable ML, suppresses false positives with process
context, and validates itself via simulated attack replay.

## Data flow (memorize this)
```
A generates → A featurizes → B scores (3 models) → D assembles Alert →
C suppresses FP → C correlates → C generates playbook → C renders UI
```

## Who owns what

| Person | Subsystem | Key files |
|---|---|---|
| A | Data + Features | `data_engine/simulator.py`, `features/preprocessor.py` |
| B | ML Models | `models/{isolation_forest,lstm_autoencoder,xgboost_classifier,shap_explainer}.py` |
| C | Correlation + UI | `engine/*.py`, `dashboard/app.py` |
| D | Simulation + Glue | `simulation/*.py`, `run.py`, `demo_script.md` |

## Contracts (frozen — don't change)

- **Event** (schema.py): A's output → everyone's input
- **FeaturePipeline.transform() → ndarray(60,)**: A's output → B's input
- **Classifier.predict() → dict{class, confidence, probabilities}**: B's output → D's input
- **Alert** (schema.py): D's output → C's input
- **Incident** (schema.py): C's output → dashboard's input

## Commands we'll demo live

```bash
streamlit run dashboard/app.py      # full UI
python run.py 100 500               # CLI — benign only, no alerts
python -m simulation.scorecard      # 6/6 attack scenarios pass
```

## Numbers to memorize

- **6/6** scenarios pass the self-validation scorecard (100%)
- **5 threat classes**: benign, brute_force, lateral_movement, data_exfiltration, c2_beaconing
- **3 signal layers**: network, endpoint, application
- **60 dims** per feature vector
- **60-second** correlation window
- **500+ ev/s** throughput target (PS requirement)
- **1-10-60** SLA: detect < 1min, investigate < 10min, remediate < 60min

## Bonus differentiators (call these out)

1. Simulation engine with self-validation scorecard (PS Bonus goal)
2. Plain-English SHAP translation (not just raw numbers)
3. FP suppression with admin + tool + destination rules (PS required scenario)
4. Process ancestry tracking (lsass→cmd is the killer signal)
5. MITRE ATT&CK tags on every playbook
6. 1-10-60 SLA tracker widget

## Known gaps (be honest if asked)

- LSTM autoencoder and XGBoost are rule-based in the demo build; real
  Keras + CICIDS2018 training is in B's Colab notebook — interface-compatible
  drop-in replacement
- FP rules are hardcoded Python; production would load from YAML
- Dashboard auto-refresh via `st.rerun()` is crude; a websocket push model
  would be lower-latency

## If asked "what would you do with more time"

1. Train real XGBoost on full CICIDS2018 (Colab queue was slow)
2. Active learning: analyst feedback loop retrains the classifier weekly
3. MITRE sub-technique mapping (T1110.001 vs T1110.003)
4. Real EDR integration (CrowdStrike / SentinelOne APIs) instead of simulated endpoints
5. Multi-tenant mode — one pipeline per customer with isolated models
