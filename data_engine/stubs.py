"""
Person A — Data & Ingestion
Owner of: data_engine/, features/

Responsibilities:
  1. Generate synthetic data with dual attack (Brute Force + C2) + admin FP
  2. Kafka-lite pub/sub using asyncio queues
  3. Normalize heterogeneous logs into Event schema
  4. Feature preprocessing: log(x+1) + RobustScaler + OneHotEncoder
  5. Prove 500+ ev/sec throughput

Contract with Person B:
  get_feature_vector(event: Event) -> np.ndarray  (shape: 40-80 dims)
  get_feature_names() -> list[str]                (for SHAP labels)
"""
from schema import Event
from typing import AsyncIterator, List
import numpy as np


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
    """
    MUST produce:
      - Benign background traffic (~95%)
      - Brute Force + C2 Beacon running CONCURRENTLY (PS requirement)
      - Lateral Movement (synthetic, since CICIDS is weak here)
      - Data Exfiltration burst
      - 1 admin bulk-transfer FP that LOOKS like exfiltration but isn't
    """
    raise NotImplementedError("Person A")


# ---------- data_engine/ingestion.py ----------
async def pubsub_stream(topic: str) -> AsyncIterator[Event]:
    """
    asyncio-based fake Kafka. Topics: topic.network, topic.endpoint, topic.application
    Must handle 500+ ev/sec without dropping.
    """
    raise NotImplementedError("Person A")
    yield  # keeps type checker happy


# ---------- data_engine/normalizer.py ----------
def normalize(raw_log: dict, layer: str) -> Event:
    """Pad missing fields with None. Output must satisfy Event schema."""
    raise NotImplementedError("Person A")


# ---------- features/preprocessor.py ----------
class FeaturePipeline:
    """
    Fit on benign traffic only, then transform everything.
    - log(x+1) for bytes_transferred, packet_count, duration, payload_size
    - RobustScaler (IQR-based) for all numerics
    - OneHotEncoder(handle_unknown='ignore') for protocol, http_method, process_name
    """
    def fit(self, events: List[Event]) -> "FeaturePipeline":
        raise NotImplementedError("Person A")

    def transform(self, event: Event) -> np.ndarray:
        """Returns fixed-size vector (40–80 dims). This is what Person B consumes."""
        raise NotImplementedError("Person A")

    def get_feature_names(self) -> List[str]:
        """Ordered list of feature names — Person C needs this for SHAP labels."""
        raise NotImplementedError("Person A")

    def save(self, path: str) -> None: ...
    def load(self, path: str) -> "FeaturePipeline": ...
