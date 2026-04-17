"""
Scenario replayer — feeds pre-built attack scenarios into the live pipeline.

Two modes:
  1. Real-time: events stream at their original timestamps (slow, realistic)
  2. Accelerated: compress time by N× for demos (e.g., 60× = 1 minute = 1 second)

The replayer is ALSO what the dashboard's "Simulation Mode" toggle drives.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, AsyncIterator, Optional

from schema import Event
from simulation.scenarios import SCENARIOS

log = logging.getLogger("replayer")


class ScenarioReplayer:
    def __init__(self, speed_multiplier: float = 10.0):
        """speed_multiplier=10 → 1 second of scenario time takes 0.1s real time."""
        self.speed = speed_multiplier

    def build(self, scenario_name: str,
              start: Optional[datetime] = None) -> List[Event]:
        """Construct a scenario's event list."""
        if scenario_name not in SCENARIOS:
            raise KeyError(f"Unknown scenario: {scenario_name}. "
                           f"Available: {list(SCENARIOS.keys())}")
        start = start or datetime.now()
        builder = SCENARIOS[scenario_name]["builder"]
        events = builder(start)
        events.sort(key=lambda e: e.timestamp)
        return events

    async def replay(self, events: List[Event]) -> AsyncIterator[Event]:
        """Stream events with inter-event delays scaled by speed_multiplier."""
        if not events:
            return
        t0 = events[0].timestamp
        real_start = datetime.now()

        for event in events:
            scenario_elapsed = (event.timestamp - t0).total_seconds()
            real_target = scenario_elapsed / self.speed
            real_elapsed = (datetime.now() - real_start).total_seconds()
            wait = real_target - real_elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            yield event

    async def replay_scenario(self, scenario_name: str) -> AsyncIterator[Event]:
        """Convenience: build + replay in one call."""
        events = self.build(scenario_name)
        log.info(f"Replaying '{scenario_name}' — {len(events)} events, "
                 f"speed={self.speed}×")
        async for e in self.replay(events):
            yield e

    async def replay_all(self) -> AsyncIterator[Event]:
        """Run every scenario sequentially. Used by the self-validation scorecard."""
        for name in SCENARIOS:
            log.info(f"▶ Scenario: {name}")
            async for event in self.replay_scenario(name):
                yield event
            await asyncio.sleep(0.5)  # small gap between scenarios
