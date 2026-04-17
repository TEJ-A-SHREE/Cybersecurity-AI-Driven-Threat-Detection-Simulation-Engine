from schema import Event
from typing import AsyncIterator, List
import numpy as np
import asyncio
import random


# ---------- data_engine/simulator.py ----------
def generate_dataset(
    duration_seconds: int = 300,
    events_per_second: int = 500,
    include_brute_force: bool = True,
    include_c2_beacon: bool = True,
    include_lateral_movement: bool = True,
    include_exfiltration: bool = True,
    include_admin_fp: bool = True,
) -> List[Event]:

    events = []
    total = duration_seconds * events_per_second

    for i in range(total):
        layer = random.choice(["network", "endpoint", "application"])

        event = Event(
            layer=layer,
            user=random.choice(["admin", "user1", "user2"]),
            bytes=random.randint(100, 20000),
            status=random.choice([200, 401]),
            process=random.choice(["", "cmd.exe", "powershell.exe"]),
            timestamp=i
        )

        events.append(event)

    return events


# ---------- data_engine/ingestion.py ----------
async def pubsub_stream(topic: str) -> AsyncIterator[Event]:

    events = generate_dataset(duration_seconds=2, events_per_second=50)

    for e in events:
        await asyncio.sleep(0)   # only change: faster
        yield e


# ---------- data_engine/normalizer.py ----------
def normalize(raw_log: dict, layer: str) -> Event:

    return Event(
        layer=layer if layer else raw_log.get("layer", ""),
        user=raw_log.get("user", ""),
        bytes=raw_log.get("bytes", 0),
        status=raw_log.get("status", 200),
        process=raw_log.get("process", ""),
        timestamp=raw_log.get("timestamp", 0)
    )


# ---------- features/preprocessor.py ----------
class FeaturePipeline:

    def fit(self, events: List[Event]) -> "FeaturePipeline":
        return self

    def transform(self, event: Event) -> np.ndarray:

        is_network = 1 if event.layer == "network" else 0
        is_endpoint = 1 if event.layer == "endpoint" else 0
        is_application = 1 if event.layer == "application" else 0

        high_bytes = 1 if event.bytes > 5000 else 0
        login_fail = 1 if event.status == 401 else 0
        suspicious_process = 1 if event.process in ["cmd.exe", "powershell.exe"] else 0

        return np.array([
            is_network,
            is_endpoint,
            is_application,
            high_bytes,
            login_fail,
            suspicious_process
        ])

    def get_feature_names(self) -> List[str]:
        return [
            "network",
            "endpoint",
            "application",
            "high_bytes",
            "login_fail",
            "suspicious_process"
        ]

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> "FeaturePipeline":
        return self
