"""
Layer 2: Feature Engineering & Preprocessing
Log-Transform, RobustScaler, One-Hot Encoding
Outputs 40-80 dim feature vectors
"""

import numpy as np
from typing import List, Dict
import math


KNOWN_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "FTP", "SSH", "SMTP"]
KNOWN_METHODS   = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
KNOWN_PROCESSES = [
    "svchost.exe", "explorer.exe", "chrome.exe", "python.exe", "cmd.exe",
    "powershell.exe", "lsass.exe", "services.exe", "winlogon.exe", "nginx",
    "apache2", "node", "java", "bash", "sh", "curl", "wget", "ssh"
]
KNOWN_COUNTRIES = ["IN", "US", "CN", "RU", "BR", "DE", "FR", "GB", "JP", "KR", "UA", "IR"]


class RobustScaler:
    """IQR-based scaler — immune to adversarial outlier injection"""
    def __init__(self):
        self.medians = {}
        self.iqrs = {}
        self._fitted = False

    def fit(self, data: List[float], key: str):
        if not data:
            return
        arr = sorted(data)
        n = len(arr)
        self.medians[key] = arr[n // 2]
        q1 = arr[n // 4]
        q3 = arr[3 * n // 4]
        self.iqrs[key] = max(q3 - q1, 1e-6)
        self._fitted = True

    def transform(self, val: float, key: str) -> float:
        if key not in self.medians:
            return 0.0
        return (val - self.medians[key]) / self.iqrs[key]


class FeaturePreprocessor:
    def __init__(self):
        self.scaler = RobustScaler()
        self._initialize_scaler()

    def _initialize_scaler(self):
        # Seed with typical baseline values
        self.scaler.fit([0, 100, 500, 1500, 5000, 50000, 1000000], "bytes_transferred")
        self.scaler.fit([1, 5, 20, 100, 500, 2000], "packet_count")
        self.scaler.fit([0, 0.1, 1, 5, 30, 300], "duration_sec")
        self.scaler.fit([100, 500, 1500, 5000, 50000], "payload_size")

    def transform(self, events: List[Dict]) -> np.ndarray:
        return np.array([self._featurize(e) for e in events], dtype=np.float32)

    def _featurize(self, e: Dict) -> List[float]:
        features = []

        # --- Numeric features (log-transformed) ---
        features.append(self._log(e.get("bytes_transferred", 0)))
        features.append(self._log(e.get("packet_count", 0)))
        features.append(self._log(e.get("duration_sec", 0) + 1))
        features.append(self._log(e.get("payload_size", 0)))
        features.append(float(e.get("src_port", 0)) / 65535.0)
        features.append(float(e.get("dst_port", 0)) / 65535.0)
        features.append(float(e.get("status_code", 200)) / 599.0)

        # RobustScaler on key fields
        features.append(self.scaler.transform(e.get("bytes_transferred", 0), "bytes_transferred"))
        features.append(self.scaler.transform(e.get("packet_count", 0), "packet_count"))
        features.append(self.scaler.transform(e.get("duration_sec", 0), "duration_sec"))

        # --- Derived / engineered features ---
        bytes_val = e.get("bytes_transferred", 1)
        duration = max(e.get("duration_sec", 1), 0.001)
        features.append(self._log(bytes_val / duration))           # throughput

        pkt = max(e.get("packet_count", 1), 1)
        features.append(self._log(bytes_val / pkt))                 # bytes per packet

        # Port risk
        dst_port = e.get("dst_port", 0)
        features.append(1.0 if dst_port in [22, 23, 3389, 5900, 4444, 1337] else 0.0)  # high-risk port
        features.append(1.0 if dst_port in [80, 443, 8080, 8443] else 0.0)               # web port
        features.append(1.0 if dst_port in [53, 67, 68] else 0.0)                        # DNS/DHCP

        # IP context
        features.append(0.0 if e.get("is_internal", True) else 1.0)  # external dst

        # IP octets (normalized)
        src_parts = self._ip_octets(e.get("src_ip", "0.0.0.0"))
        dst_parts = self._ip_octets(e.get("dst_ip", "0.0.0.0"))
        features.extend(src_parts + dst_parts)  # 8 features

        # --- One-hot: Protocol ---
        proto = (e.get("protocol") or "").upper()
        features.extend([1.0 if proto == p else 0.0 for p in KNOWN_PROTOCOLS])

        # --- One-hot: HTTP Method ---
        method = (e.get("http_method") or "").upper()
        features.extend([1.0 if method == m else 0.0 for m in KNOWN_METHODS])

        # --- One-hot: Source layer ---
        layer = e.get("source_layer", "network")
        features.extend([
            1.0 if layer == "network" else 0.0,
            1.0 if layer == "endpoint" else 0.0,
            1.0 if layer == "application" else 0.0,
        ])

        # --- One-hot: Process name (top processes) ---
        proc = (e.get("process_name") or "").lower()
        features.extend([1.0 if proc == p.lower() else 0.0 for p in KNOWN_PROCESSES])

        # --- One-hot: Geo country ---
        country = (e.get("geo_country") or "")
        features.extend([1.0 if country == c else 0.0 for c in KNOWN_COUNTRIES])

        # --- Time features ---
        try:
            from datetime import datetime
            ts = datetime.fromisoformat(e.get("timestamp", datetime.now().isoformat()))
            features.append(ts.hour / 24.0)
            features.append(ts.weekday() / 7.0)
            # Off-hours flag (unusual activity time)
            features.append(1.0 if ts.hour < 6 or ts.hour > 22 else 0.0)
        except Exception:
            features.extend([0.5, 0.5, 0.0])

        # Flags bitmask
        flags = e.get("flags", [])
        features.append(1.0 if "SYN" in flags else 0.0)
        features.append(1.0 if "RST" in flags else 0.0)
        features.append(1.0 if "FIN" in flags else 0.0)

        return features

    def _log(self, val: float) -> float:
        return math.log1p(max(float(val), 0))

    def _ip_octets(self, ip: str) -> List[float]:
        try:
            parts = ip.split(".")
            return [int(p) / 255.0 for p in parts[:4]]
        except Exception:
            return [0.0, 0.0, 0.0, 0.0]
