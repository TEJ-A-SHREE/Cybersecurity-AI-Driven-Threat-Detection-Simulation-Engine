"""
Threat Simulator
Generates realistic synthetic events for demo and training:
- Benign traffic
- Brute Force
- C2 Beaconing
- Data Exfiltration
- Lateral Movement
Also seeds: simultaneous attack scenarios + realistic false positive
"""

import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Tuple

# Realistic IP pools
INTERNAL_IPS = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(50)]
EXTERNAL_IPS = [
    "45.79.23.11", "185.220.101.45", "91.108.56.130", "198.51.100.42",
    "203.0.113.77", "104.21.55.200", "172.67.185.52", "8.8.8.8",
    "1.1.1.1", "94.102.49.190", "31.13.72.36", "77.88.8.8",
]
C2_IPS = ["45.79.23.11", "185.220.101.45", "91.108.56.130", "103.22.200.198"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.68.0", "python-requests/2.28.0", "Go-http-client/1.1",
]

PROCESSES = ["svchost.exe", "explorer.exe", "chrome.exe", "python.exe",
             "cmd.exe", "powershell.exe", "services.exe", "nginx", "bash"]


def _ts(offset_sec: float = 0) -> str:
    return (datetime.now() - timedelta(seconds=offset_sec)).isoformat()


class ThreatSimulator:

    # ────────────────────────────────────────────
    # Benign traffic
    # ────────────────────────────────────────────
    def generate_benign_traffic(self, n: int = 200) -> List[Dict]:
        events = []
        for _ in range(n):
            layer = random.choice(["network", "endpoint", "application"])
            if layer == "network":
                events.append(self._benign_network())
            elif layer == "endpoint":
                events.append(self._benign_endpoint())
            else:
                events.append(self._benign_application())
        return events

    def _benign_network(self) -> Dict:
        return {
            "source_layer": "network",
            "timestamp": _ts(random.uniform(0, 300)),
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": random.choice(INTERNAL_IPS + ["8.8.8.8", "1.1.1.1"]),
            "src_port": random.randint(1024, 60000),
            "dst_port": random.choice([80, 443, 53, 22, 8080]),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
            "bytes": random.randint(100, 50000),
            "packets": random.randint(1, 200),
            "duration": random.uniform(0.1, 30),
            "flags": ["SYN", "ACK"],
        }

    def _benign_endpoint(self) -> Dict:
        return {
            "source_layer": "endpoint",
            "timestamp": _ts(random.uniform(0, 300)),
            "host_ip": random.choice(INTERNAL_IPS),
            "process_name": random.choice(["svchost.exe", "explorer.exe", "chrome.exe", "nginx", "bash"]),
            "parent_pid": random.randint(1, 1000),
            "user": random.choice(["alice", "bob", "svc_web", "admin"]),
            "bytes_written": random.randint(0, 10000),
        }

    def _benign_application(self) -> Dict:
        return {
            "source_layer": "application",
            "timestamp": _ts(random.uniform(0, 300)),
            "client_ip": random.choice(INTERNAL_IPS),
            "server_ip": "10.0.0.1",
            "method": random.choice(["GET", "POST"]),
            "path": random.choice(["/api/data", "/health", "/login", "/users"]),
            "status": random.choice([200, 200, 200, 201, 204]),
            "payload_size": random.randint(100, 5000),
            "user_agent": USER_AGENTS[0],
            "geo": "IN",
        }

    # ────────────────────────────────────────────
    # Attack scenarios
    # ────────────────────────────────────────────
    def generate_scenario(self, scenario: str, n: int = 100) -> List[Dict]:
        generators = {
            "brute_force":       self._gen_brute_force,
            "c2_beacon":         self._gen_c2_beacon,
            "lateral_movement":  self._gen_lateral_movement,
            "exfiltration":      self._gen_exfiltration,
        }
        gen = generators.get(scenario, self._gen_brute_force)
        return [gen() for _ in range(n)]

    def _gen_brute_force(self) -> Dict:
        return {
            "source_layer": "application",
            "timestamp": _ts(random.uniform(0, 60)),
            "client_ip": random.choice(EXTERNAL_IPS),
            "server_ip": "10.0.0.50",
            "method": "POST",
            "path": "/login",
            "status": random.choice([401, 401, 401, 403, 200]),
            "payload_size": random.randint(50, 300),
            "user_agent": random.choice(USER_AGENTS),
            "geo": random.choice(["RU", "CN", "UA", "IR"]),
        }

    def _gen_c2_beacon(self) -> Dict:
        c2_ip = random.choice(C2_IPS)
        # Very regular interval: every 60±5 seconds
        return {
            "source_layer": "network",
            "timestamp": _ts(random.uniform(0, 5)),
            "src_ip": "10.0.1.42",
            "dst_ip": c2_ip,
            "src_port": random.randint(49000, 65535),
            "dst_port": random.choice([443, 8443, 4444, 1337, 8080]),
            "protocol": "TCP",
            "bytes": random.randint(200, 500),
            "packets": random.randint(3, 8),
            "duration": random.uniform(0.5, 2.0),
            "flags": ["PSH", "ACK"],
            "process_name": "svchost.exe",
        }

    def _gen_lateral_movement(self) -> Dict:
        src = random.choice(INTERNAL_IPS[:10])
        dst = random.choice(INTERNAL_IPS[10:])
        return {
            "source_layer": "network",
            "timestamp": _ts(random.uniform(0, 120)),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(49000, 65535),
            "dst_port": random.choice([445, 135, 139, 3389, 5985]),
            "protocol": "TCP",
            "bytes": random.randint(5000, 100000),
            "packets": random.randint(50, 500),
            "duration": random.uniform(2, 60),
            "flags": ["SYN", "ACK", "PSH"],
            "process_name": "powershell.exe",
            "user": "compromised_svc",
        }

    def _gen_exfiltration(self) -> Dict:
        return {
            "source_layer": "network",
            "timestamp": _ts(random.uniform(0, 180)),
            "src_ip": "10.0.2.15",
            "dst_ip": random.choice(EXTERNAL_IPS),
            "src_port": random.randint(49000, 65535),
            "dst_port": random.choice([443, 21, 22, 80]),
            "protocol": random.choice(["TCP", "HTTPS", "FTP"]),
            "bytes": random.randint(50_000_000, 500_000_000),  # 50MB–500MB
            "packets": random.randint(10000, 100000),
            "duration": random.uniform(10, 300),
            "flags": ["ACK", "PSH"],
        }

    # ────────────────────────────────────────────
    # False positive: admin bulk transfer
    # ────────────────────────────────────────────
    def generate_admin_false_positive(self) -> Dict:
        return {
            "source_layer": "network",
            "timestamp": _ts(0),
            "src_ip": "10.0.0.100",
            "dst_ip": "10.0.0.200",  # internal backup server
            "src_port": 49152,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes": 120_000_000,  # 120MB — looks like exfiltration
            "packets": 90000,
            "duration": 600,
            "flags": ["ACK"],
            "process_name": "robocopy.exe",
            "user": "backup",
        }

    # ────────────────────────────────────────────
    # Mixed traffic stream (for live demo)
    # ────────────────────────────────────────────
    def generate_mixed_traffic(self, n: int = 50) -> List[Dict]:
        events = []
        for _ in range(n):
            r = random.random()
            if r < 0.70:
                events.append(self._benign_network())
            elif r < 0.80:
                events.append(self._benign_application())
            elif r < 0.87:
                events.append(self._gen_brute_force())
            elif r < 0.92:
                events.append(self._gen_c2_beacon())
            elif r < 0.96:
                events.append(self._gen_lateral_movement())
            elif r < 0.99:
                events.append(self._gen_exfiltration())
            else:
                events.append(self.generate_admin_false_positive())
        return events

    # ────────────────────────────────────────────
    # Labeled dataset for XGBoost training
    # ────────────────────────────────────────────
    def generate_labeled_dataset(self, n_per_class: int = 300) -> Tuple[List[Dict], List[str]]:
        events, labels = [], []

        benign = self.generate_benign_traffic(n_per_class)
        events.extend(benign)
        labels.extend(["Benign"] * len(benign))

        for threat, gen in [
            ("Brute Force",      self._gen_brute_force),
            ("C2 Beaconing",     self._gen_c2_beacon),
            ("Lateral Movement", self._gen_lateral_movement),
            ("Data Exfiltration",self._gen_exfiltration),
        ]:
            for _ in range(n_per_class):
                events.append(gen())
                labels.append(threat)

        return events, labels
