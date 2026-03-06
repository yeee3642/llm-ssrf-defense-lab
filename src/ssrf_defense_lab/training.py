from __future__ import annotations

import json
from pathlib import Path

from .models import Scenario
from .repair import build_patch_hint, build_repair_playbook

SYSTEM_PROMPT = (
    "You are an SSRF defense agent for production web applications. "
    "Given a server-side fetch scenario, decide whether to allow, review, or block it, "
    "explain the risk briefly, and return concrete repair actions that preserve the feature."
)


def build_training_target(scenario: Scenario) -> dict[str, object]:
    confidence_map = {"allow": 0.89, "review": 0.84, "block": 0.96}
    analysis_map = {
        "allow": "The destination remains on an approved external path and the surrounding controls reduce SSRF exposure.",
        "review": "The request is not overtly malicious, but the feature needs destination validation and bounded outbound fetch controls.",
        "block": "The request crosses a high-confidence SSRF boundary such as an internal host, unsafe scheme, or redirect-to-internal path.",
    }
    repairs = build_repair_playbook(scenario.framework, scenario.required_repairs)
    return {
        "action": scenario.expected_action,
        "confidence": confidence_map[scenario.expected_action],
        "analysis": analysis_map[scenario.expected_action],
        "repair_tokens": list(scenario.required_repairs),
        "proposed_repairs": repairs,
        "patch_hint": build_patch_hint(scenario.framework, scenario.required_repairs),
    }


def export_training_jsonl(scenarios: list[Scenario], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for scenario in scenarios:
            record = {
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(scenario.to_prompt_dict(), ensure_ascii=True)},
                    {"role": "assistant", "content": json.dumps(build_training_target(scenario), ensure_ascii=True)},
                ],
                "metadata": {
                    "scenario_id": scenario.scenario_id,
                    "framework": scenario.framework,
                    "expected_action": scenario.expected_action,
                },
            }
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
