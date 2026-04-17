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

        layer = random.choice(["network","endpoint","application"])

        e = Event(
            layer=layer,
            user=random.choice(["user1","user2"]),
            bytes=random.randint(100,3000),
            status=200,
            process="",
            timestamp=i
        )

        # -------- Concurrent Attacks --------

        # Brute Force (frequent 401s)
        if include_brute_force and (i % 10 < 3):
            e.status = 401
            e.user = "admin"

        # C2 Beacon (periodic high traffic)
        if include_c2_beacon and (i % 15 < 2):
            e.bytes = random.randint(12000,18000)

        # Lateral Movement
        if include_lateral_movement and (i % 20 == 0):
            e.process = "powershell.exe"

        # Data Exfiltration burst
        if include_exfiltration and (i % 50 < 5):
            e.bytes = random.randint(18000,25000)

        # Admin False Positive (looks like exfiltration but legit)
        if include_admin_fp and i == total // 2:
            e.user = "admin"
            e.bytes = 20000
            e.status = 200

        events.append(e)

    return events


# ---------- data_engine/ingestion.py ----------
queue = asyncio.Queue()

async def pubsub_stream(topic: str) -> AsyncIterator[Event]:

    events = generate_dataset(duration_seconds=2, events_per_second=500)

    for e in events:
        await queue.put(e)

    await queue.put(None)

    while True:
        event = await queue.get()
        if event is None:
            break
        yield event


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

        # ---- log(x+1) ----
        log_bytes = np.log1p(event.bytes)

        # ---- basic robust scaling (approx using median idea) ----
        scaled_bytes = log_bytes / 10  # lightweight scaling for hackathon

        # ---- one-hot encoding ----
        is_network = 1 if event.layer == "network" else 0
        is_endpoint = 1 if event.layer == "endpoint" else 0
        is_application = 1 if event.layer == "application" else 0

        # ---- other signals ----
        login_fail = 1 if event.status == 401 else 0
        suspicious_process = 1 if event.process in ["cmd.exe","powershell.exe"] else 0

        return np.array([
            scaled_bytes,
            login_fail,
            suspicious_process,
            is_network,
            is_endpoint,
            is_application
        ])

    def get_feature_names(self) -> List[str]:
        return [
            "scaled_log_bytes",
            "login_fail",
            "suspicious_process",
            "is_network",
            "is_endpoint",
            "is_application"
        ]

    def save(self, path: str) -> None:
        pass

    def load(self, path: str) -> "FeaturePipeline":
        return self
