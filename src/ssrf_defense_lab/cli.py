from __future__ import annotations

import argparse
from pathlib import Path

from .agent import SyntheticLLMDefenseAgent
from .baseline import TraditionalSSRFDefender
from .benchmark import compare_reports, evaluate_engine, write_json_report, write_markdown_report
from .scenarios import load_default_scenarios
from .training import export_training_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and evaluate an LLM-centered SSRF defense benchmark.")
    parser.add_argument(
        "--training-output",
        type=Path,
        default=Path("data/ssrf_defense_training.jsonl"),
        help="Where to write the synthetic training dataset.",
    )
    parser.add_argument(
        "--json-report",
        type=Path,
        default=Path("reports/latest_report.json"),
        help="Where to write the machine-readable benchmark report.",
    )
    parser.add_argument(
        "--markdown-report",
        type=Path,
        default=Path("reports/latest_report.md"),
        help="Where to write the human-readable benchmark report.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    scenarios = load_default_scenarios()

    export_training_jsonl(scenarios, args.training_output)

    baseline = TraditionalSSRFDefender()
    llm_agent = SyntheticLLMDefenseAgent()

    baseline_report = evaluate_engine("traditional-baseline", baseline, scenarios)
    llm_report = evaluate_engine("llm-defense-agent", llm_agent, scenarios)
    comparison = compare_reports(baseline_report, llm_report)

    write_json_report(comparison, args.json_report)
    write_markdown_report(comparison, args.markdown_report)

    print(f"Wrote training set: {args.training_output}")
    print(f"Wrote JSON report: {args.json_report}")
    print(f"Wrote markdown report: {args.markdown_report}")
    print(
        "LLM agent deltas -> "
        f"unsafe_f1: {comparison.improvements['unsafe_f1_delta']:+.4f}, "
        f"action_accuracy: {comparison.improvements['action_accuracy_delta']:+.4f}, "
        f"repair_coverage: {comparison.improvements['repair_coverage_delta']:+.4f}, "
        f"adaptability: {comparison.improvements['adaptability_delta']:+.4f}"
    )


if __name__ == "__main__":
    main()
