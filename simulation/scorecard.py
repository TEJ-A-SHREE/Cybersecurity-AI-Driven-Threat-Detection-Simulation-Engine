"""
Self-validation scorecard — runs every scenario through the pipeline and
reports detection rate, latency, confidence, and FP suppression.

This is the core of the Bonus stretch goal:
  "Threat simulation mode with self-validation"

Display as a dashboard tab. Print to terminal during CI/pre-demo checks.
"""
import asyncio
import time
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional

from schema import Alert
from simulation.replayer import ScenarioReplayer
from simulation.scenarios import SCENARIOS

log = logging.getLogger("scorecard")


@dataclass
class ScenarioResult:
    name: str
    expected_class: object           # str OR list[str]
    expected_detected: bool
    is_fp_test: bool = False

    # Outcomes
    alerts_raised: int = 0
    classes_detected: List[str] = field(default_factory=list)
    max_confidence: float = 0.0
    first_detection_latency_s: Optional[float] = None

    @property
    def passed(self) -> bool:
        if self.is_fp_test:
            # FP scenario: should NOT produce any alerts
            return self.alerts_raised == 0
        # Attack scenario: should detect expected class(es)
        if isinstance(self.expected_class, list):
            return all(c in self.classes_detected for c in self.expected_class)
        return self.expected_class in self.classes_detected

    @property
    def summary(self) -> str:
        if self.is_fp_test:
            return ("SUPPRESSED ✓" if self.passed
                    else f"LEAKED ({self.alerts_raised} false alerts) ✗")
        if not self.passed:
            return f"MISSED ✗ (expected {self.expected_class})"
        lat = f"{self.first_detection_latency_s:.2f}s" if self.first_detection_latency_s else "?"
        return f"DETECTED ✓ ({lat}, conf={self.max_confidence:.2f})"


class SelfValidationScorecard:
    def __init__(self, pipeline, speed_multiplier: float = 50.0):
        """
        pipeline: a DetectionPipeline instance (from run.py)
        speed_multiplier: how fast to replay. 50× = fast enough for demos
        """
        self.pipeline = pipeline
        self.replayer = ScenarioReplayer(speed_multiplier=speed_multiplier)
        self.results: Dict[str, ScenarioResult] = {}

    async def run_scenario(self, name: str) -> ScenarioResult:
        spec = SCENARIOS[name]
        result = ScenarioResult(
            name=name,
            expected_class=spec["expected_class"],
            expected_detected=spec["expected_detected"],
            is_fp_test=spec.get("is_fp_test", False),
        )

        scenario_start = time.time()
        events = self.replayer.build(name)

        async for event in self.replayer.replay(events):
            alert: Optional[Alert] = self.pipeline.process(event)
            if alert is None:
                continue
            result.alerts_raised += 1
            result.classes_detected.append(alert.threat_class)
            result.max_confidence = max(result.max_confidence,
                                         alert.class_confidence)
            if result.first_detection_latency_s is None:
                result.first_detection_latency_s = time.time() - scenario_start

        self.results[name] = result
        return result

    async def run_all(self) -> Dict[str, ScenarioResult]:
        log.info("=" * 60)
        log.info("SELF-VALIDATION SCORECARD")
        log.info("=" * 60)
        for name in SCENARIOS:
            log.info(f"▶ {name} ...")
            result = await self.run_scenario(name)
            log.info(f"  {result.summary}")
        self._print_report()
        return self.results

    def _print_report(self):
        print("\n" + "=" * 70)
        print(f"{'SCENARIO':<22} {'RESULT':<40} {'PASS?':<8}")
        print("-" * 70)
        for r in self.results.values():
            mark = "✓ PASS" if r.passed else "✗ FAIL"
            print(f"{r.name:<22} {r.summary:<40} {mark:<8}")
        print("-" * 70)
        total = len(self.results)
        passed = sum(1 for r in self.results.values() if r.passed)
        pct = 100.0 * passed / total if total else 0.0
        print(f"OVERALL: {passed}/{total} passed  ({pct:.0f}%)")
        print("=" * 70 + "\n")

    def to_dict(self) -> dict:
        """JSON-serializable version for the dashboard."""
        return {
            "results": {k: asdict(v) for k, v in self.results.items()},
            "total": len(self.results),
            "passed": sum(1 for r in self.results.values() if r.passed),
            "generated_at": datetime.now().isoformat(),
        }


# ============================================================
# Standalone entry point — run without dashboard
# ============================================================
async def main():
    from run import DetectionPipeline
    pipeline = DetectionPipeline()
    scorecard = SelfValidationScorecard(pipeline, speed_multiplier=100.0)
    await scorecard.run_all()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(main())
