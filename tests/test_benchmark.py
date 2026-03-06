from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ssrf_defense_lab.agent import SyntheticLLMDefenseAgent
from ssrf_defense_lab.baseline import TraditionalSSRFDefender
from ssrf_defense_lab.benchmark import compare_reports, evaluate_engine
from ssrf_defense_lab.scenarios import load_default_scenarios
from ssrf_defense_lab.training import export_training_jsonl


class BenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenarios = load_default_scenarios()

    def test_baseline_blocks_loopback(self) -> None:
        baseline = TraditionalSSRFDefender()
        decision = baseline.analyze(self.scenarios[0])
        self.assertEqual(decision.action, "block")

    def test_llm_agent_improves_action_accuracy_and_repairs(self) -> None:
        baseline_report = evaluate_engine("traditional-baseline", TraditionalSSRFDefender(), self.scenarios)
        llm_report = evaluate_engine("llm-defense-agent", SyntheticLLMDefenseAgent(), self.scenarios)
        comparison = compare_reports(baseline_report, llm_report)

        self.assertGreater(llm_report.action_accuracy, baseline_report.action_accuracy)
        self.assertGreaterEqual(llm_report.repair_coverage, baseline_report.repair_coverage)
        self.assertGreaterEqual(comparison.improvements["adaptability_delta"], 0.0)

    def test_training_export_writes_one_record_per_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "training.jsonl"
            export_training_jsonl(self.scenarios, output)
            lines = output.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), len(self.scenarios))
            first = json.loads(lines[0])
            self.assertIn("messages", first)
            self.assertEqual(first["metadata"]["scenario_id"], self.scenarios[0].scenario_id)


if __name__ == "__main__":
    unittest.main()
