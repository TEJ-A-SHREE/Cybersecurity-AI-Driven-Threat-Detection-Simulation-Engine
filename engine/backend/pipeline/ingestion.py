"""
Layer 1: Multi-Signal Ingestion & Normalization
Handles network, endpoint, and application layer logs
"""

import uuid
from datetime import datetime
from typing import List, Dict, Any


UNIFIED_SCHEMA = {
    "event_id": None,
    "timestamp": None,
    "source_layer": None,       # network | endpoint | application
    "src_ip": None,
    "dst_ip": None,
    "src_port": None,
    "dst_port": None,
    "protocol": None,
    "bytes_transferred": 0,
    "packet_count": 0,
    "duration_sec": 0,
    "flags": [],
    "process_name": None,
    "parent_pid": None,
    "user": None,
    "file_access": None,
    "registry_change": None,
    "http_method": None,
    "endpoint_path": None,
    "status_code": None,
    "payload_size": 0,
    "user_agent": None,
    "geo_country": None,
    "is_internal": True,
}


class EventIngester:
    def normalize(self, events: List[Dict], source_layer: str) -> List[Dict]:
        normalized = []
        for raw in events:
            event = dict(UNIFIED_SCHEMA)
            event["event_id"] = str(uuid.uuid4())[:8]
            event["timestamp"] = raw.get("timestamp", datetime.now().isoformat())
            event["source_layer"] = raw.get("source_layer", source_layer)

            if source_layer == "network":
                event.update(self._parse_network(raw))
            elif source_layer == "endpoint":
                event.update(self._parse_endpoint(raw))
            elif source_layer == "application":
                event.update(self._parse_application(raw))
            else:
                # Auto-detect based on fields
                if "process_name" in raw:
                    event.update(self._parse_endpoint(raw))
                elif "http_method" in raw:
                    event.update(self._parse_application(raw))
                else:
                    event.update(self._parse_network(raw))

            event["is_internal"] = self._is_internal(event.get("dst_ip", ""))
            normalized.append(event)
        return normalized

    def _parse_network(self, raw: Dict) -> Dict:
        return {
            "src_ip": raw.get("src_ip", "0.0.0.0"),
            "dst_ip": raw.get("dst_ip", "0.0.0.0"),
            "src_port": raw.get("src_port", 0),
            "dst_port": raw.get("dst_port", 0),
            "protocol": raw.get("protocol", "TCP"),
            "bytes_transferred": raw.get("bytes", raw.get("bytes_transferred", 0)),
            "packet_count": raw.get("packets", raw.get("packet_count", 0)),
            "duration_sec": raw.get("duration", raw.get("duration_sec", 0)),
            "flags": raw.get("flags", []),
            "source_layer": "network",
        }

    def _parse_endpoint(self, raw: Dict) -> Dict:
        return {
            "src_ip": raw.get("host_ip", "10.0.0.1"),
            "dst_ip": raw.get("dst_ip", ""),
            "process_name": raw.get("process_name", "unknown"),
            "parent_pid": raw.get("parent_pid", 0),
            "user": raw.get("user", "system"),
            "file_access": raw.get("file_access", None),
            "registry_change": raw.get("registry_change", None),
            "bytes_transferred": raw.get("bytes_written", 0),
            "source_layer": "endpoint",
        }

    def _parse_application(self, raw: Dict) -> Dict:
        return {
            "src_ip": raw.get("client_ip", raw.get("src_ip", "0.0.0.0")),
            "dst_ip": raw.get("server_ip", raw.get("dst_ip", "10.0.0.1")),
            "http_method": raw.get("method", raw.get("http_method", "GET")),
            "endpoint_path": raw.get("path", raw.get("endpoint_path", "/")),
            "status_code": raw.get("status", raw.get("status_code", 200)),
            "payload_size": raw.get("payload_size", raw.get("response_size", 0)),
            "user_agent": raw.get("user_agent", ""),
            "geo_country": raw.get("geo", raw.get("geo_country", "IN")),
            "source_layer": "application",
        }

    def _is_internal(self, ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                               "172.18.", "172.19.", "172.20.", "172.21.",
                               "172.22.", "172.23.", "172.24.", "172.25.",
                               "172.26.", "172.27.", "172.28.", "172.29.",
                               "172.30.", "172.31."))
