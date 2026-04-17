"""
Attack scenarios — scripted event sequences that simulate real attacks.

Each scenario is a list of events with precise timing. The replayer
streams them through the pipeline at configurable speed and the scorecard
validates whether the pipeline caught them.

This is the heart of the simulation engine — the Bonus stretch goal in
the problem statement: "Threat simulation mode with self-validation".
"""
from datetime import datetime, timedelta
from typing import List, Dict, Callable
from schema import Event, ThreatClass
import uuid


def _eid() -> str:
    return f"evt-{uuid.uuid4().hex[:8]}"


# ============================================================
# Scenario 1: SSH Brute Force
# ============================================================
def brute_force_ssh(start: datetime, target_ip: str = "10.0.1.50",
                    attacker_ip: str = "185.220.101.45",
                    attempts: int = 40) -> List[Event]:
    """Rapid-fire failed SSH auth from single external IP."""
    events = []
    for i in range(attempts):
        t = start + timedelta(milliseconds=200 * i)
        events.append(Event(
            event_id=_eid(), timestamp=t, layer="network",
            src_ip=attacker_ip, dst_ip=target_ip,
            src_port=50000 + i, dst_port=22,
            protocol="TCP", bytes_transferred=128,
            packet_count=3, duration=0.05, tcp_flags="SYN,ACK,RST",
        ))
        # Paired auth failure log from application layer
        events.append(Event(
            event_id=_eid(), timestamp=t + timedelta(milliseconds=50),
            layer="application",
            src_ip=attacker_ip, dst_ip=target_ip,
            http_method="POST", endpoint="/ssh/auth",
            status_code=401, payload_size=64,
            user_agent="OpenSSH-client", geolocation="RU",
        ))
    return events


# ============================================================
# Scenario 2: C2 Beaconing (DNS tunneling)
# ============================================================
def c2_beacon_dns(start: datetime, compromised_host: str = "10.0.3.21",
                  c2_server: str = "45.79.23.11",
                  beacons: int = 12, interval_s: int = 30) -> List[Event]:
    """Low-volume periodic outbound to same external IP — classic C2."""
    events = []
    for i in range(beacons):
        t = start + timedelta(seconds=interval_s * i)

        # Endpoint: suspicious process spawning network activity
        events.append(Event(
            event_id=_eid(), timestamp=t, layer="endpoint",
            process_name="svchost.exe", pid=3841,
            parent_pid=892, parent_process="services.exe",
            user="SYSTEM",
        ))

        # Network: the beacon itself — small, periodic
        events.append(Event(
            event_id=_eid(), timestamp=t + timedelta(milliseconds=100),
            layer="network",
            src_ip=compromised_host, dst_ip=c2_server,
            src_port=49000 + i, dst_port=53,
            protocol="UDP", bytes_transferred=312,
            packet_count=2, duration=0.12,
        ))
    return events


# ============================================================
# Scenario 3: Lateral Movement (SMB/RDP east-west)
# ============================================================
def lateral_movement_smb(start: datetime, foothold: str = "10.0.1.45",
                          targets: List[str] = None) -> List[Event]:
    """Compromised host scanning + connecting to internal peers."""
    targets = targets or [f"10.0.1.{i}" for i in (12, 23, 31, 47, 52)]
    events = []
    t = start

    # Endpoint: lsass spawning cmd — the classic credential-theft signature
    events.append(Event(
        event_id=_eid(), timestamp=t, layer="endpoint",
        process_name="cmd.exe", pid=5102,
        parent_pid=3841, parent_process="lsass.exe",  # ⚠ lsass should NOT spawn shells
        user="admin",
    ))

    # Network: SMB port 445 connections fanning out to internal IPs
    for i, target in enumerate(targets):
        events.append(Event(
            event_id=_eid(),
            timestamp=t + timedelta(seconds=3 + i * 2),
            layer="network",
            src_ip=foothold, dst_ip=target,
            src_port=51000 + i, dst_port=445,
            protocol="TCP", bytes_transferred=8500,
            packet_count=14, duration=1.8,
        ))
    return events


# ============================================================
# Scenario 4: Data Exfiltration
# ============================================================
def data_exfiltration(start: datetime, internal_host: str = "10.0.2.88",
                       external_dst: str = "91.108.56.9") -> List[Event]:
    """Large outbound transfer to external IP, off-hours."""
    events = []
    t = start

    # Application: unusual API call pattern
    events.append(Event(
        event_id=_eid(), timestamp=t, layer="application",
        src_ip=internal_host, dst_ip=external_dst,
        http_method="POST", endpoint="/upload/bulk",
        status_code=200, payload_size=312_000_000,   # 312 MB
        user_agent="curl/7.81.0", geolocation="XX",
    ))

    # Network: sustained outbound flow
    events.append(Event(
        event_id=_eid(), timestamp=t + timedelta(seconds=1),
        layer="network",
        src_ip=internal_host, dst_ip=external_dst,
        src_port=52100, dst_port=443,
        protocol="TCP", bytes_transferred=312_000_000,
        packet_count=215_000, duration=180.0,
    ))
    return events


# ============================================================
# Scenario 5: Admin False Positive (PS REQUIREMENT)
# ============================================================
def admin_bulk_transfer_fp(start: datetime) -> List[Event]:
    """
    A legit admin doing a backup that SUPERFICIALLY looks like exfiltration.
    Key differences the FP filter must catch:
      - user = "admin" (allowlisted)
      - process = "rsync" (allowed tool)
      - dst = internal backup server (10.0.x.x, known-good)
      - scheduled time matches admin cron window
    """
    events = []
    t = start
    events.append(Event(
        event_id=_eid(), timestamp=t, layer="endpoint",
        process_name="rsync", pid=8102,
        parent_pid=1, parent_process="cron",
        user="admin",
    ))
    events.append(Event(
        event_id=_eid(), timestamp=t + timedelta(seconds=1),
        layer="network",
        src_ip="10.0.2.88", dst_ip="10.0.99.5",       # internal backup
        src_port=53000, dst_port=873,                  # rsync port
        protocol="TCP", bytes_transferred=500_000_000,
        packet_count=340_000, duration=240.0,
    ))
    return events


# ============================================================
# DUAL ATTACK — PS hard requirement
# ============================================================
def dual_attack_bf_plus_c2(start: datetime) -> List[Event]:
    """Brute Force + C2 Beacon running concurrently. PS requirement."""
    events = []
    events.extend(brute_force_ssh(start))
    # C2 beacon starts 5 seconds into the brute force
    events.extend(c2_beacon_dns(start + timedelta(seconds=5)))
    events.sort(key=lambda e: e.timestamp)
    return events


# ============================================================
# Registry — all scenarios keyed by name, for the scorecard
# ============================================================
SCENARIOS: Dict[str, Dict] = {
    "brute_force": {
        "builder": brute_force_ssh,
        "expected_class": "brute_force",
        "expected_detected": True,
    },
    "c2_beaconing": {
        "builder": c2_beacon_dns,
        "expected_class": "c2_beaconing",
        "expected_detected": True,
    },
    "lateral_movement": {
        "builder": lateral_movement_smb,
        "expected_class": "lateral_movement",
        "expected_detected": True,
    },
    "data_exfiltration": {
        "builder": data_exfiltration,
        "expected_class": "data_exfiltration",
        "expected_detected": True,
    },
    "admin_fp": {
        "builder": admin_bulk_transfer_fp,
        "expected_class": "benign",         # should be suppressed as FP
        "expected_detected": False,          # pipeline should NOT raise alert
        "is_fp_test": True,
    },
    "dual_attack": {
        "builder": dual_attack_bf_plus_c2,
        "expected_class": ["brute_force", "c2_beaconing"],
        "expected_detected": True,
    },
}
