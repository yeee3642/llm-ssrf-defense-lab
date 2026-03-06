# LLM SSRF Defense Lab

`LLM SSRF Defense Lab` is a synthetic training and evaluation harness for an LLM-centered SSRF defense agent. It benchmarks a context-aware agent against a traditional rule-based baseline across mixed Web application environments and produces training data, machine-readable reports, and a human-readable assessment.

## What it validates

- automated SSRF detection, interception, and triage across Flask, Django, FastAPI, Express, Spring Boot, and Next.js API surfaces
- contextual analysis of URL, DNS, redirect-chain, code-path, and deployment signals
- repair guidance that stays aligned with the framework handling the outbound request
- measurable differences between an adaptive LLM-style agent and a fixed traditional ruleset

## Current benchmark snapshot

Generated from `reports/latest_report.md`.

| Engine | Unsafe F1 | Action Accuracy | Block Recall | Repair Coverage | Adaptability |
| --- | ---: | ---: | ---: | ---: | ---: |
| traditional-baseline | 0.9474 | 0.8571 | 0.8750 | 0.7583 | 0.8889 |
| llm-defense-agent | 1.0000 | 1.0000 | 1.0000 | 0.9750 | 1.0000 |

Observed gains from the LLM-driven agent:

- catches public-looking callback verification flows that still need SSRF review
- catches open-redirect broker probes that can land on localhost after the first hop
- emits broader repair coverage, especially DNS pinning, redirect validation, and timeout caps
- maintains full accuracy across all included framework families in the synthetic suite

## Project layout

- `src/ssrf_defense_lab/scenarios.py` - synthetic SSRF and benign fetch scenarios
- `src/ssrf_defense_lab/baseline.py` - traditional rule-based defender
- `src/ssrf_defense_lab/agent.py` - adaptive LLM-style defender with contextual reasoning
- `src/ssrf_defense_lab/training.py` - JSONL training export for fine-tuning or regression sets
- `src/ssrf_defense_lab/benchmark.py` - metrics, comparison, and report generation
- `scripts/train_benchmark.py` - one-shot entry point to regenerate artifacts
- `reports/latest_report.md` - latest human-readable evaluation
- `data/ssrf_defense_training.jsonl` - generated training corpus

## Run it

```bash
python3 scripts/train_benchmark.py
python3 -m unittest discover -s tests
```

## How the evaluation works

1. Each scenario encodes framework context, route purpose, outbound client, URL target, redirect behavior, DNS outcome, and expected defender action.
2. The traditional baseline applies mostly static SSRF rules such as scheme denial, private-address blocking, and redirect suspicion.
3. The LLM-style agent adds contextual reasoning over fetch surface, allowlist presence, tenant risk, nested redirect targets, and repair selection.
4. The benchmark compares unsafe detection, exact action choice, block recall, repair coverage, and per-framework adaptability.

## Notes

- This repository stays on the defensive side: it models SSRF risk signals and remediation strategies rather than shipping exploit automation.
- The default agent is deterministic so you can regression-test it offline. You can replace it with a live model adapter later if you want to compare real LLM inference.
