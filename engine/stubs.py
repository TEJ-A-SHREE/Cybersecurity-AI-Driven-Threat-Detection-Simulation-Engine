"""
Person C — Correlation, Explainability & Dashboard
Owner of: engine/, dashboard/

Responsibilities:
  1. Cross-layer correlation (60s sliding window + PID/PPID ancestry)
  2. Plain-English SHAP translator ("Unusually large outbound transfer...")
  3. False positive suppressor (Admin + Known IP + Allowed Tool rules)
  4. MITRE ATT&CK mapping (mitre_mapping.json)
  5. Streamlit dashboard with live feed, 1-10-60 tracker, SHAP bars, playbook panel
  6. Playbook template engine with variable interpolation

Contract with Person B: consumes Alert objects
Contract with Person D: exposes render_dashboard(alerts, incidents) for demo mode
"""
from schema import Alert, Incident, Event
from typing import List
from datetime import timedelta


# ---------- engine/correlation.py ----------
class CorrelationEngine:
    """
    Sliding window join across layers. When network + endpoint alerts
    reference the same asset within 60s → merge into an Incident with
    boosted confidence.
    """
    def __init__(self, window: timedelta = timedelta(seconds=60)):
        self.window = window
        self.buffer: List[Alert] = []

    def ingest(self, alert: Alert) -> List[Incident]:
        """Returns list of newly-formed or updated Incidents."""
        raise NotImplementedError("Person C")

    def _track_process_ancestry(self, alert: Alert) -> dict:
        """
        PID → PPID → PPPID chain. Flags suspicious parent-child pairs:
          lsass.exe → cmd.exe          (credential access → shell)
          svchost.exe → powershell.exe (service → scripting)
          word.exe → cmd.exe           (doc macro → shell)
        """
        raise NotImplementedError("Person C")


# ---------- engine/shap_translator.py ----------
def shap_to_english(top_features: dict, threat_class: str) -> str:
    """
    Translates SHAP top features into a sentence.
    Examples:
      {'beacon_interval_regularity': 0.82, 'dst_ip_reputation': 0.74}
        → "Periodic outbound connections to a low-reputation IP at regular
           intervals — classic C2 beaconing pattern."

      {'outbound_bytes': 0.67, 'off_hours': 0.55}
        → "Large outbound transfer (312MB) outside business hours to an
           external destination."
    """
    raise NotImplementedError("Person C")


# ---------- engine/fp_suppressor.py ----------
class FalsePositiveFilter:
    """
    Rules that suppress obvious FPs:
      1. User is in admin_allowlist
      2. Destination IP is in known_good_ips
      3. Process is in allowed_tools (rsync, rclone, aws-cli, etc.)
      4. Activity matches a scheduled admin task
    """
    def __init__(self, config_path: str = "engine/fp_config.yaml"):
        raise NotImplementedError("Person C")

    def check(self, alert: Alert, event: Event) -> tuple[bool, str]:
        """Returns (is_fp, reason). reason = '' if not FP."""
        raise NotImplementedError("Person C")


# ---------- engine/mitre_mapping.json (data file, not code) ----------
MITRE_MAPPING_TEMPLATE = {
    "brute_force": {
        "tactics": ["TA0006"],          # Credential Access
        "techniques": ["T1110"],        # Brute Force
        "sub_techniques": ["T1110.001", "T1110.003"]
    },
    "lateral_movement": {
        "tactics": ["TA0008"],          # Lateral Movement
        "techniques": ["T1021", "T1570"]
    },
    "data_exfiltration": {
        "tactics": ["TA0010"],          # Exfiltration
        "techniques": ["T1041", "T1048"]
    },
    "c2_beaconing": {
        "tactics": ["TA0011"],          # Command and Control
        "techniques": ["T1071", "T1059"]
    }
}


# ---------- engine/playbook_generator.py ----------
class PlaybookGenerator:
    """
    Loads playbook_templates.yaml keyed by (threat_class, severity).
    Interpolates {dst_ip}, {pid}, {hostname}, {user} from incident context.
    """
    def __init__(self, template_path: str = "engine/playbook_templates.yaml"):
        raise NotImplementedError("Person C")

    def generate(self, incident: Incident) -> dict:
        """
        Returns:
          {
            "title": "C2 Beaconing — Critical",
            "mitre": ["T1071", "T1059", "TA0011"],
            "steps": [
              "Isolate 192.168.1.47 from network segment immediately",
              "Block egress to 45.79.23.11 at perimeter firewall",
              ...
            ]
          }
        """
        raise NotImplementedError("Person C")


# ---------- dashboard/app.py ----------
def run_dashboard():
    """
    Streamlit app. Required widgets (match the PPT slide 20 mockup):
      - Top metrics row: EVENTS/SEC, OPEN INCIDENTS, MEAN DETECT TIME,
                        FP SUPPRESSED, OVERALL CONFIDENCE
      - Left: REAL-TIME EVENT FEED (scrolling alerts with severity chips)
      - Right: 3-PHASE PIPELINE indicator + 1-10-60 SLA TRACKER
      - Bottom-left: SHAP EXPLAINABILITY waterfall bars
      - Bottom-right: AUTO PLAYBOOK with MITRE chips + numbered steps
    """
    raise NotImplementedError("Person C")
