"""
AI-Driven Threat Detection & Simulation Engine
Backend API — FastAPI + ML Pipeline
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import json
import random
import time
import threading
from datetime import datetime, timedelta
from collections import deque

from pipeline.ingestion import EventIngester
from pipeline.preprocessor import FeaturePreprocessor
from pipeline.detector import AnomalyDetector
from pipeline.classifier import ThreatClassifier
from pipeline.correlator import CrossLayerCorrelator
from pipeline.explainer import SHAPExplainer
from pipeline.playbook import PlaybookGenerator
from pipeline.simulator import ThreatSimulator

app = FastAPI(title="AI Threat Detection Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
ingester = EventIngester()
preprocessor = FeaturePreprocessor()
detector = AnomalyDetector()
classifier = ThreatClassifier()
correlator = CrossLayerCorrelator()
explainer = SHAPExplainer()
playbook_gen = PlaybookGenerator()
simulator = ThreatSimulator()

# In-memory incident store
incident_store = deque(maxlen=500)
stats = {
    "events_per_sec": 0,
    "open_incidents": 0,
    "mean_detect_time": 0.7,
    "fp_suppressed": 0,
    "overall_confidence": 89,
}

# WebSocket connections
active_connections: List[WebSocket] = []


class EventBatch(BaseModel):
    events: List[Dict[str, Any]]
    source: str = "network"


class SimulationRequest(BaseModel):
    scenario: str  # "brute_force", "c2_beacon", "lateral_movement", "exfiltration"
    intensity: int = 50  # events per second
    duration: int = 10   # seconds


@app.get("/health")
async def health():
    return {"status": "operational", "timestamp": datetime.now().isoformat()}


@app.get("/stats")
async def get_stats():
    stats["open_incidents"] = len([i for i in incident_store if i["status"] == "open"])
    return stats


@app.get("/incidents")
async def get_incidents(limit: int = 50, severity: Optional[str] = None):
    incidents = list(incident_store)
    if severity:
        incidents = [i for i in incidents if i.get("severity") == severity.upper()]
    return {"incidents": incidents[-limit:], "total": len(incidents)}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    for incident in incident_store:
        if incident["id"] == incident_id:
            return incident
    return JSONResponse(status_code=404, content={"error": "Incident not found"})


@app.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str):
    for incident in incident_store:
        if incident["id"] == incident_id:
            incident["status"] = "acknowledged"
            return {"success": True}
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.post("/ingest")
async def ingest_events(batch: EventBatch, background_tasks: BackgroundTasks):
    background_tasks.add_task(process_batch, batch.events, batch.source)
    return {"accepted": len(batch.events), "status": "queued"}


@app.post("/simulate")
async def start_simulation(req: SimulationRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_simulation, req.scenario, req.intensity, req.duration)
    return {"status": "simulation_started", "scenario": req.scenario}


@app.get("/playbook/{incident_id}")
async def get_playbook(incident_id: str):
    for incident in incident_store:
        if incident["id"] == incident_id:
            pb = playbook_gen.generate(incident)
            return {"playbook": pb}
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.websocket("/ws/live-feed")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast(message: dict):
    for conn in active_connections[:]:
        try:
            await conn.send_json(message)
        except Exception:
            if conn in active_connections:
                active_connections.remove(conn)


async def process_batch(events: list, source: str):
    t_start = time.time()
    normalized = ingester.normalize(events, source)
    features = preprocessor.transform(normalized)
    anomaly_scores = detector.score(features)
    flagged = [e for e, s in zip(normalized, anomaly_scores) if s > 0.5]
    if not flagged:
        return

    classifications = classifier.classify(flagged, features[:len(flagged)])
    correlated = correlator.correlate(classifications)

    for incident in correlated:
        explanation = explainer.explain(incident)
        incident["explanation"] = explanation
        incident["playbook_steps"] = playbook_gen.generate(incident)
        incident["detect_time_ms"] = round((time.time() - t_start) * 1000, 1)
        incident_store.append(incident)
        stats["open_incidents"] += 1

        # Broadcast to WebSocket clients
        asyncio.create_task(broadcast({
            "type": "new_incident",
            "incident": incident
        }))


async def run_simulation(scenario: str, intensity: int, duration: int):
    events = simulator.generate_scenario(scenario, intensity * duration)
    await process_batch(events, "simulated")
    asyncio.create_task(broadcast({
        "type": "simulation_complete",
        "scenario": scenario,
        "events_generated": intensity * duration
    }))


# Background event generator for demo
def start_demo_stream():
    async def _stream():
        while True:
            await asyncio.sleep(1)
            batch = simulator.generate_mixed_traffic(random.randint(20, 80))
            await process_batch(batch, "network")
            stats["events_per_sec"] = random.randint(480, 540)
            await broadcast({"type": "stats_update", "stats": stats})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_stream())


@app.on_event("startup")
async def startup():
    detector.fit_baseline()
    classifier.load_or_train()
    asyncio.create_task(demo_stream_task())


async def demo_stream_task():
    while True:
        await asyncio.sleep(1)
        batch = simulator.generate_mixed_traffic(random.randint(20, 80))
        await process_batch(batch, "network")
        stats["events_per_sec"] = random.randint(480, 540)
        await broadcast({"type": "stats_update", "stats": stats})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
