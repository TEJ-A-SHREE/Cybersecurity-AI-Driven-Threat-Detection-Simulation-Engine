"""
Unified event schema — THE contract between all subsystems.
Do not modify without telling the whole team.

Owner: Person A (Data) — but reviewed by all 4.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal, Dict, Any
from datetime import datetime
import json

Layer = Literal["network", "endpoint", "application"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ThreatClass = Literal[
    "benign",
    "brute_force",
    "lateral_movement",
    "data_exfiltration",
    "c2_beaconing",
]


@dataclass
class Event:
    """Unified event after Person A's normalizer. Missing fields = None."""
    event_id: str
    timestamp: datetime
    layer: Layer

    # Network fields
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None         # TCP/UDP/ICMP
    bytes_transferred: Optional[int] = None
    packet_count: Optional[int] = None
    duration: Optional[float] = None
    tcp_flags: Optional[str] = None

    # Endpoint fields
    process_name: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    parent_process: Optional[str] = None
    user: Optional[str] = None
    file_accessed: Optional[str] = None
    registry_key: Optional[str] = None

    # Application fields
    http_method: Optional[str] = None      # GET/POST/PUT
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    payload_size: Optional[int] = None
    user_agent: Optional[str] = None
    geolocation: Optional[str] = None

    def to_json(self) -> str:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return json.dumps(d)


@dataclass
class Alert:
    """What the ML pipeline emits. Consumed by correlation + dashboard."""
    alert_id: str
    event_id: str                  # FK back to Event
    timestamp: datetime
    layer: Layer

    # ML outputs
    anomaly_confidence: float      # 0.0–1.0 (Isolation Forest + LSTM ensemble)
    threat_class: ThreatClass      # from XGBoost
    class_confidence: float        # 0.0–1.0 probability
    severity: Severity             # derived from class × confidence

    # Explainability
    shap_top_features: Dict[str, float] = field(default_factory=dict)
    plain_english_reason: str = ""
    mitre_tactics: list = field(default_factory=list)      # e.g. ["TA0008"]
    mitre_techniques: list = field(default_factory=list)   # e.g. ["T1021"]

    # Correlation / FP
    correlated_alerts: list = field(default_factory=list)  # list of alert_ids
    is_false_positive: bool = False
    fp_reason: Optional[str] = None


@dataclass
class Incident:
    """A correlated cluster of alerts. This is what shows in the SOC feed."""
    incident_id: str
    created_at: datetime
    threat_class: ThreatClass
    severity: Severity
    confidence: float
    alerts: list                   # list of Alert objects
    affected_assets: list = field(default_factory=list)
    playbook: Optional[Dict[str, Any]] = None
