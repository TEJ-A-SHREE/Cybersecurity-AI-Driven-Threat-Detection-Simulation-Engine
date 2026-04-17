"""
run.py — THE orchestrator. Integrated version with all 4 subsystems wired up.

Design principle: this file ALWAYS runs. Swap fake implementations for real
ones by changing a single import line. Shape never changes.
"""
import asyncio
import logging
import uuid
from collections import deque
from datetime import datetime
from typing import Deque, List, Optional

import numpy as np

from schema import Event, Alert, Incident

# Person A
from data_engine.simulator import pubsub_stream
from features.preprocessor import FeaturePipeline

# Person B
from models.isolation_forest import IsoForestDetector
from models.lstm_autoencoder import LSTMAutoencoder
from models.xgboost_classifier import ThreatClassifier
from models.shap_explainer import ShapExplainer
from models.stubs import derive_severity

# Person C
from engine.correlation import CorrelationEngine
from engine.fp_suppressor import FalsePositiveFilter
from engine.shap_translator import shap_to_english
from engine.playbook_generator import PlaybookGenerator
from engine.stubs import MITRE_MAPPING_TEMPLATE as MITRE_MAPPING


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("engine")


class PipelineState:
    """Shared state. Dashboard reads from this; pipeline writes to this."""
    def __init__(self):
        self.events_processed: int = 0
        self.alerts_raised: int = 0
        self.fps_suppressed: int = 0
        self.incidents: List[Incident] = []
        self.recent_alerts: Deque[Alert] = deque(maxlen=100)
        self.started_at = datetime.now()

    @property
    def events_per_second(self) -> float:
        elapsed = (datetime.now() - self.started_at).total_seconds()
        return self.events_processed / max(elapsed, 1.0)


STATE = PipelineState()


class DetectionPipeline:
    ANOMALY_THRESHOLD = 0.3

    def __init__(self):
        self.pipeline = FeaturePipeline()
        self.iforest = IsoForestDetector()
        self.lstm_ae = LSTMAutoencoder()
        self.classifier = ThreatClassifier()
        self.explainer = ShapExplainer(
            classifier=self.classifier,
            feature_names=self.pipeline.get_feature_names(),
        )
        self.correlator = CorrelationEngine(window_seconds=60)
        self.fp_filter = FalsePositiveFilter()
        self.playbook_gen = PlaybookGenerator()
        self.sequence_buffer: Deque[np.ndarray] = deque(maxlen=10)

    def process(self, event: Event) -> Optional[Alert]:
        STATE.events_processed += 1

        # Stage 2: Featurize
        features = self.pipeline.transform(event)
        self.sequence_buffer.append(features)

        # Stage 3: Ensemble anomaly detection
        iso_score = self.iforest.anomaly_score(features)
        lstm_score = 0.0
        if len(self.sequence_buffer) >= 3:
            seq = np.stack(list(self.sequence_buffer))
            lstm_score = self.lstm_ae.anomaly_score(seq)
        anomaly_conf = max(iso_score, lstm_score)

        if anomaly_conf < self.ANOMALY_THRESHOLD:
            return None

        # Stage 4: Classify
        pred = self.classifier.predict(features)
        if pred["class"] == "benign":
            return None

        # Stage 6a: Explain
        explanation = self.explainer.explain(features)
        threat_class = pred["class"]
        severity = derive_severity(threat_class, pred["confidence"])
        mitre = MITRE_MAPPING.get(threat_class, {"tactics": [], "techniques": []})

        alert = Alert(
            alert_id=f"alt-{uuid.uuid4().hex[:8]}",
            event_id=event.event_id,
            timestamp=event.timestamp,
            layer=event.layer,
            anomaly_confidence=anomaly_conf,
            threat_class=threat_class,
            class_confidence=pred["confidence"],
            severity=severity,
            shap_top_features=explanation["top_features"],
            plain_english_reason=shap_to_english(
                explanation["top_features"], threat_class),
            mitre_tactics=mitre.get("tactics", []),
            mitre_techniques=mitre.get("techniques", []),
        )

        # Stage 6b: FP suppression
        is_fp, reason = self.fp_filter.check(alert, event)
        if is_fp:
            alert.is_false_positive = True
            alert.fp_reason = reason
            STATE.fps_suppressed += 1
            log.info(f"[FP SUPPRESSED] {threat_class} — {reason}")
            return None

        # Stage 5: Cross-layer correlation → Incidents
        new_incidents = self.correlator.ingest(alert)
        for inc in new_incidents:
            inc.playbook = self.playbook_gen.generate(inc)
            if inc not in STATE.incidents:
                STATE.incidents.append(inc)

        # Stage 7: Emit for dashboard
        STATE.alerts_raised += 1
        STATE.recent_alerts.append(alert)
        return alert


async def main(events_per_second: int = 50, max_events: Optional[int] = None):
    log.info(f"Starting detection pipeline @ {events_per_second} ev/sec target")
    pipeline = DetectionPipeline()
    count = 0

    async for event in pubsub_stream(events_per_second=events_per_second):
        alert = pipeline.process(event)
        if alert:
            log.warning(
                f"🚨 [{alert.severity:8s}] {alert.threat_class:20s} "
                f"conf={alert.class_confidence:.2f} "
                f"anomaly={alert.anomaly_confidence:.2f} · "
                f"{alert.plain_english_reason[:90]}"
            )
        count += 1
        if max_events and count >= max_events:
            break
        if count % 200 == 0:
            log.info(f"Throughput: {STATE.events_per_second:.0f} ev/s | "
                     f"alerts={STATE.alerts_raised} "
                     f"fps={STATE.fps_suppressed} "
                     f"incidents={len(STATE.incidents)}")


if __name__ == "__main__":
    import sys
    eps = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    maxe = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    try:
        asyncio.run(main(events_per_second=eps, max_events=maxe))
    except KeyboardInterrupt:
        log.info("Shutdown requested")
    log.info(f"Final: {STATE.events_processed} events, "
             f"{STATE.alerts_raised} alerts, "
             f"{STATE.fps_suppressed} FPs suppressed, "
             f"{len(STATE.incidents)} incidents")
