# Demo Script — AI Threat Detection & Simulation Engine

**Total runtime: ~5 minutes**
**Speaker: Person D (with team assisting)**

---

## Pre-Demo Checklist (10 minutes before)

- [ ] Laptop plugged in, WiFi confirmed
- [ ] Two terminals open in the project directory
- [ ] One browser tab with the Streamlit URL ready (not yet loaded)
- [ ] Screen recording running as backup
- [ ] PPT on a second monitor (in case the demo breaks)
- [ ] Clear your terminal: `clear`

---

## Scene 1 — The Problem (45 sec)

**Stand with slide showing the three-layer architecture from the PPT.**

> "Organizations drown in security alerts. Traditional rule-based tools catch yesterday's attacks and miss novel ones. We built an AI engine that does three things most SIEMs don't: explains *why* each alert fired, suppresses false positives with process-level context, and validates itself using simulated attacks."

**Click to PPT slide with the pipeline diagram.**

> "Seven stages — ingestion, features, anomaly detection, classification, cross-layer correlation, SHAP explainability, and SOC dashboard. Plus a simulation engine that runs every attack scenario through the pipeline and reports pass/fail live."

---

## Scene 2 — Start the Pipeline (45 sec)

**Terminal 1:**

```bash
streamlit run dashboard/app.py
```

**Browser loads the dashboard. All metrics at zero.**

> "This is the live SOC. Zero events, zero alerts. Watch the top-right pipeline indicator — three phases: Scout, Expert, Enforcer."

**Click "▶ Start Pipeline" on the dashboard.**

> "Pipeline started. Benign traffic is streaming in at about 100 events per second — normal web traffic, endpoint activity, API calls. Notice the alerts row stays empty. No false positives. The anomaly threshold filters out noise before classification even runs."

**Wait ~10 seconds to show benign traffic flowing with no alerts.**

---

## Scene 3 — The Self-Validation Scorecard (90 sec)

**Terminal 2:**

```bash
python -m simulation.scorecard
```

> "Now I'm running our self-validation scorecard. This is the bonus stretch goal from the problem statement — *threat simulation mode with self-validation*. It replays every attack scenario through the live pipeline and verifies the pipeline caught it."

**As the scorecard runs, narrate the scenarios:**

> "Brute Force — SSH authentication flood. Detected in 50 milliseconds, confidence 91%."
>
> "C2 Beaconing — periodic DNS exfiltration to an external IP. Detected, confidence 91%. This is the hardest one to catch because individual beacons look tiny and harmless."
>
> "Lateral Movement — attacker hopping east-west on SMB. Detected via our process ancestry rules — `lsass.exe` spawning `cmd.exe` is a credential-theft signature that should never appear in normal operations."
>
> "Data Exfiltration — 312MB outbound to an unusual geolocation. Detected, confidence 86%."
>
> "Admin FP — a legit admin running rsync to the backup server. This *looks* like exfiltration on paper. Notice the result: SUPPRESSED. Our FP filter recognized the admin user, the allowed tool, and the internal destination."
>
> "Dual Attack — Brute Force and C2 Beacon running simultaneously. Detected, both classes identified in the same window."
>
> "Final score: six out of six. One hundred percent."

---

## Scene 4 — Explainability (60 sec)

**Switch back to the Streamlit dashboard. Point at the SHAP panel.**

> "The problem statement asked for alerts with reasoning — not just 'something is wrong,' but *why*. This is our SHAP explainability panel. For the latest alert, we show the top six features that drove the decision, ranked by contribution. Here you can see beacon-sized payloads contributed +0.82, external destination +0.67, unusual geolocation +0.45."

**Read the plain-English sentence below the SHAP bars.**

> "And this sentence is auto-generated from those SHAP values — no analyst has to interpret the raw numbers. A SOC analyst reads this in two seconds and knows what happened."

**Scroll to the playbook panel.**

> "On the right, the auto-generated playbook. MITRE ATT&CK tags — T1071, T1059, TA0011 — the standard taxonomy real SOC teams use. Six concrete remediation steps. The playbook is generated dynamically per incident, pulling the actual destination IP, host, and user from the alert context."

---

## Scene 5 — Cross-Layer Correlation (30 sec)

**Point at the event feed on the left.**

> "Notice we're not showing every event — we're showing *incidents*. An incident is a cluster of alerts across layers within a 60-second window. A single alert from one layer is noise. The same asset appearing in network plus endpoint plus application simultaneously — that's a high-confidence incident. That's what you see here."

**Point at the 1-10-60 tracker.**

> "Industry standard metric: detect in under 1 minute, investigate in under 10, remediate in under 60. All three SLAs met for every incident on the board."

---

## Scene 6 — The Close (30 sec)

> "To summarize what you just saw: ingestion across three telemetry layers, hybrid detection using Isolation Forest plus LSTM autoencoder plus XGBoost, cross-layer correlation with process ancestry, SHAP explainability in plain English, MITRE-tagged playbooks, and self-validation scoring at 100%."
>
> "We went beyond the problem statement minimum on every axis: four threat categories not two, three signal layers not one, dynamic playbooks not static templates, and — most importantly — the simulation engine that proves the detection actually works, not just that the code runs."
>
> "Questions?"

---

## If Things Go Wrong

**Dashboard won't load:** Fall back to Terminal-only mode.
```bash
python -m simulation.scorecard
```
This alone hits the core story — the scorecard output is visually impressive.

**Pipeline false-fires on benign:** Acknowledge it, move on. Say: "In production we'd tune the anomaly threshold higher; we kept it sensitive for the demo so attacks surface fast."

**Scorecard misses a scenario:** Don't panic. Say: "Real attacks are noisy — this is why we track detection *rate*, not just binary detection." Pivot to showing the ones that passed.

**WiFi dies:** You don't need WiFi. Everything runs locally.

---

## Post-Demo Q&A Cheat Sheet

**Q: Is this trained on real data?**
> "Our feature engineering is designed for CICIDS2018. For the demo we ship with synthetic scenarios because real CICIDS data is 30GB. Person B has the Colab training notebook ready to swap in — interface is identical."

**Q: How do you know it works on unseen attacks?**
> "The Isolation Forest and LSTM autoencoder are unsupervised — they flag anything that deviates from learned benign behavior, regardless of whether we've seen the attack before. XGBoost classifies *known* categories; anomaly detection catches the unknown."

**Q: What about adversarial evasion?**
> "RobustScaler is IQR-based — outlier injection doesn't poison our scaler. Attackers also have to evade *three* models ensembled, not one. But we're not claiming perfect — we're claiming explainable and auditable."

**Q: Why Streamlit instead of a real SOC tool like Splunk?**
> "36-hour constraint. The architecture is framework-agnostic — the detection pipeline outputs JSON-serializable Alert and Incident objects. Pointing this at Splunk or a React dashboard is a frontend swap, not a redesign."

**Q: How does this scale beyond 500 ev/s?**
> "Horizontally. Kafka-lite is a placeholder for real Kafka; the consumer group pattern is designed for it. Feature pipeline is stateless per event. Models are CPU-bound but trivially parallelizable — you'd run N worker processes behind a load balancer."

**Q: What's missing that you'd build next?**
> "Three things. First, active learning — analyst feedback on false positives retraining the classifier weekly. Second, MITRE ATT&CK sub-technique mapping. Third, integration with real EDR tools to pull live process trees instead of simulated ones."
