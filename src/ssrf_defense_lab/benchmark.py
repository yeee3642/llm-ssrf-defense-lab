from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import DefenseDecision, Scenario


class Analyzer(Protocol):
    def analyze(self, scenario: Scenario) -> DefenseDecision:
        raise NotImplementedError


@dataclass
class EngineReport:
    engine: str
    unsafe_precision: float
    unsafe_recall: float
    unsafe_f1: float
    action_accuracy: float
    block_recall: float
    repair_coverage: float
    adaptability_score: float
    scenario_results: list[dict[str, Any]]
    per_framework_accuracy: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComparisonReport:
    baseline: EngineReport
    llm_agent: EngineReport
    improvements: dict[str, float]
    scenario_deltas: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_dict(),
            "llm_agent": self.llm_agent.to_dict(),
            "improvements": dict(self.improvements),
            "scenario_deltas": list(self.scenario_deltas),
        }


def evaluate_engine(engine_name: str, analyzer: Analyzer, scenarios: list[Scenario]) -> EngineReport:
    tp = fp = fn = 0
    exact_matches = 0
    block_hits = 0
    block_total = 0
    repair_scores: list[float] = []
    per_framework_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    scenario_results: list[dict[str, Any]] = []

    for scenario in scenarios:
        decision = analyzer.analyze(scenario)
        expected_unsafe = scenario.unsafe_expected
        predicted_unsafe = decision.predicted_unsafe

        if predicted_unsafe and expected_unsafe:
            tp += 1
        elif predicted_unsafe and not expected_unsafe:
            fp += 1
        elif not predicted_unsafe and expected_unsafe:
            fn += 1

        if decision.action == scenario.expected_action:
            exact_matches += 1
            per_framework_counts[scenario.framework][0] += 1
        per_framework_counts[scenario.framework][1] += 1

        if scenario.expected_action == "block":
            block_total += 1
            if decision.action == "block":
                block_hits += 1

        if scenario.required_repairs:
            overlap = len(set(decision.repair_tokens) & set(scenario.required_repairs))
            repair_scores.append(overlap / len(scenario.required_repairs))

        scenario_results.append(
            {
                "scenario_id": scenario.scenario_id,
                "framework": scenario.framework,
                "expected_action": scenario.expected_action,
                "predicted_action": decision.action,
                "correct": decision.action == scenario.expected_action,
                "score": round(decision.score, 4),
                "confidence": round(decision.confidence, 4),
                "indicators": list(decision.indicators),
                "repair_tokens": list(decision.repair_tokens),
                "analysis": decision.analysis,
            }
        )

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    action_accuracy = _safe_divide(exact_matches, len(scenarios))
    block_recall = _safe_divide(block_hits, block_total)
    repair_coverage = _average(repair_scores)
    per_framework_accuracy = {
        framework: round(_safe_divide(correct, total), 4)
        for framework, (correct, total) in per_framework_counts.items()
    }
    adaptability_score = _average(list(per_framework_accuracy.values()))

    return EngineReport(
        engine=engine_name,
        unsafe_precision=round(precision, 4),
        unsafe_recall=round(recall, 4),
        unsafe_f1=round(f1, 4),
        action_accuracy=round(action_accuracy, 4),
        block_recall=round(block_recall, 4),
        repair_coverage=round(repair_coverage, 4),
        adaptability_score=round(adaptability_score, 4),
        scenario_results=scenario_results,
        per_framework_accuracy=per_framework_accuracy,
    )


def compare_reports(baseline: EngineReport, llm_agent: EngineReport) -> ComparisonReport:
    baseline_rows = {row["scenario_id"]: row for row in baseline.scenario_results}
    llm_rows = {row["scenario_id"]: row for row in llm_agent.scenario_results}
    scenario_deltas: list[dict[str, Any]] = []

    for scenario_id in baseline_rows:
        baseline_row = baseline_rows[scenario_id]
        llm_row = llm_rows[scenario_id]
        if baseline_row["predicted_action"] == llm_row["predicted_action"] and baseline_row["correct"] == llm_row["correct"]:
            continue
        scenario_deltas.append(
            {
                "scenario_id": scenario_id,
                "expected_action": baseline_row["expected_action"],
                "baseline_action": baseline_row["predicted_action"],
                "llm_action": llm_row["predicted_action"],
                "baseline_correct": baseline_row["correct"],
                "llm_correct": llm_row["correct"],
            }
        )

    improvements = {
        "unsafe_f1_delta": round(llm_agent.unsafe_f1 - baseline.unsafe_f1, 4),
        "action_accuracy_delta": round(llm_agent.action_accuracy - baseline.action_accuracy, 4),
        "block_recall_delta": round(llm_agent.block_recall - baseline.block_recall, 4),
        "repair_coverage_delta": round(llm_agent.repair_coverage - baseline.repair_coverage, 4),
        "adaptability_delta": round(llm_agent.adaptability_score - baseline.adaptability_score, 4),
    }

    return ComparisonReport(
        baseline=baseline,
        llm_agent=llm_agent,
        improvements=improvements,
        scenario_deltas=scenario_deltas,
    )


def write_json_report(report: ComparisonReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_markdown_report(report: ComparisonReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# LLM SSRF Defense Evaluation",
        "",
        "## Metrics",
        "",
        "| Engine | Unsafe F1 | Action Accuracy | Block Recall | Repair Coverage | Adaptability |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {report.baseline.engine} | {report.baseline.unsafe_f1:.4f} | {report.baseline.action_accuracy:.4f} | "
            f"{report.baseline.block_recall:.4f} | {report.baseline.repair_coverage:.4f} | {report.baseline.adaptability_score:.4f} |"
        ),
        (
            f"| {report.llm_agent.engine} | {report.llm_agent.unsafe_f1:.4f} | {report.llm_agent.action_accuracy:.4f} | "
            f"{report.llm_agent.block_recall:.4f} | {report.llm_agent.repair_coverage:.4f} | {report.llm_agent.adaptability_score:.4f} |"
        ),
        "",
        "## Delta",
        "",
    ]

    for key, value in report.improvements.items():
        lines.append(f"- {key}: {value:+.4f}")

    lines.extend(
        [
            "",
            "## Scenario Deltas",
            "",
            "| Scenario | Expected | Baseline | LLM Agent |",
            "| --- | --- | --- | --- |",
        ]
    )

    if report.scenario_deltas:
        for delta in report.scenario_deltas:
            lines.append(
                f"| {delta['scenario_id']} | {delta['expected_action']} | {delta['baseline_action']} | {delta['llm_action']} |"
            )
    else:
        lines.append("| none | - | - | - |")

    lines.extend(
        [
            "",
            "## Framework Adaptability",
            "",
            "| Framework | Baseline Accuracy | LLM Agent Accuracy |",
            "| --- | ---: | ---: |",
        ]
    )

    frameworks = sorted(set(report.baseline.per_framework_accuracy) | set(report.llm_agent.per_framework_accuracy))
    for framework in frameworks:
        lines.append(
            f"| {framework} | {report.baseline.per_framework_accuracy.get(framework, 0.0):.4f} | {report.llm_agent.per_framework_accuracy.get(framework, 0.0):.4f} |"
        )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _average(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)
