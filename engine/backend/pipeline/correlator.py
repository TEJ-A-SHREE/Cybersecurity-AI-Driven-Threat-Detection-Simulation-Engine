"""
Layer 5: Cross-Layer Correlation Engine
Correlates incidents across network + endpoint + application layers
Single-layer alert = noise; multi-layer = high-confidence incident
"""

import time
from typing import List, Dict
from collections import defaultdict
from datetime import datetime, timedelta


CORRELATION_WINDOW_SEC = 300  # 5 minutes
CONFIDENCE_BOOST = {
    2: 0.15,   # 2-layer correlation → +15% confidence
    3: 0.25,   # 3-layer correlation → +25% confidence
}


class CrossLayerCorrelator:
    def __init__(self):
        self._pending: Dict[str, List[Dict]] = defaultdict(list)  # key: src_ip
        self._window = CORRELATION_WINDOW_SEC

    def correlate(self, incidents: List[Dict]) -> List[Dict]:
        """
        Group incidents by source IP within a time window.
        Boost confidence if same IP appears across multiple layers.
        """
        if not incidents:
            return []

        # Index new incidents by src_ip
        for incident in incidents:
            src = incident.get("src_ip", "unknown")
            self._pending[src].append(incident)

        # Prune old incidents outside the window
        self._prune_old()

        correlated = []
        for incident in incidents:
            src = incident.get("src_ip", "unknown")
            peer_incidents = self._pending.get(src, [])

            # Find unique layers this IP has triggered
            active_layers = set(p.get("source_layer") for p in peer_incidents)
            layer_count = len(active_layers)

            # Boost confidence based on cross-layer correlation
            boost = CONFIDENCE_BOOST.get(layer_count, 0.0)
            incident["confidence"] = min(1.0, incident.get("confidence", 0.5) + boost)

            # Add correlation context
            incident["correlated_layers"] = list(active_layers)
            incident["correlation_count"] = layer_count
            incident["is_correlated"] = layer_count > 1

            # Escalate severity if correlated across layers
            if layer_count >= 2 and incident["severity"] == "MEDIUM":
                incident["severity"] = "HIGH"
                incident["escalation_reason"] = f"Same source IP active across {layer_count} layers"
            elif layer_count >= 3 and incident["severity"] in ("MEDIUM", "HIGH"):
                incident["severity"] = "CRITICAL"
                incident["escalation_reason"] = "Confirmed multi-layer attack chain"

            # Build incident timeline
            incident["incident_timeline"] = self._build_timeline(peer_incidents)

            correlated.append(incident)

        return correlated

    def _prune_old(self):
        cutoff = time.time() - self._window
        for src in list(self._pending.keys()):
            try:
                self._pending[src] = [
                    inc for inc in self._pending[src]
                    if self._parse_ts(inc.get("timestamp", "")) > cutoff
                ]
                if not self._pending[src]:
                    del self._pending[src]
            except Exception:
                pass

    def _parse_ts(self, ts_str: str) -> float:
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return time.time()

    def _build_timeline(self, incidents: List[Dict]) -> List[Dict]:
        sorted_events = sorted(incidents, key=lambda x: x.get("timestamp", ""))
        return [
            {
                "time": inc.get("timestamp", ""),
                "layer": inc.get("source_layer", ""),
                "threat": inc.get("threat_type", ""),
                "severity": inc.get("severity", ""),
            }
            for inc in sorted_events[-10:]  # last 10 events
        ]
