# LLM SSRF Defense Lab

An evaluation harness for SSRF defense across mixed web-application surfaces. It
scores a **context-aware defender** against a traditional rule-based baseline on a
synthetic scenario corpus, and emits training data, machine-readable reports, and a
human-readable assessment.

> **Read this before the numbers.** The defender in this repo (`agent.py`) is a
> **deterministic hand-written rule set, not a language model.** It is named
> `llm-defense-agent` in the reports because it encodes the behaviour a model-driven
> defender would have to reach — it is the *target specification*, not a measurement
> of an LLM. Two structural limits follow from that, and they bound how the results
> below can be read:
>
> 1. **The defender is a superset of the baseline by construction.** It wraps
>    `TraditionalSSRFDefender` and only ever adds indicators and score. It therefore
>    cannot score lower than the baseline on these metrics — the comparison shows the
>    *size* of the gap the extra context signals open up, not that one approach beat
>    another in open competition.
> 2. **The scenario corpus is the tuning set.** All 14 scenarios in `scenarios.py`
>    were hand-authored alongside the defender, and the training JSONL is the same 14
>    cases. The 1.0000 figures are in-sample and are **not** a generalization claim.
>    Treat them as "the rules cover the cases they were written for."
>
> Making this an actual LLM benchmark requires a live model adapter, a held-out
> scenario split, and an attacker that adapts to the defender. None of those are
> here yet.

## What it models

- SSRF detection, interception, and triage across Flask, Django, FastAPI, Express,
  Spring Boot, and Next.js API surfaces
- contextual analysis of URL, DNS, redirect-chain, code-path, and deployment signals
- repair guidance that stays aligned with the framework handling the outbound request
- the measurable gap between a context-aware ruleset and a fixed traditional one

## In-sample benchmark snapshot

Regenerate with `scripts/train_benchmark.py`, which writes into `reports/`
(gitignored — see Notes). **In-sample on all 14 tuning scenarios — see the caveat
above.**

| Engine | Unsafe F1 | Action Accuracy | Block Recall | Repair Coverage | Adaptability |
| --- | ---: | ---: | ---: | ---: | ---: |
| traditional-baseline | 0.9474 | 0.8571 | 0.8750 | 0.7583 | 0.8889 |
| llm-defense-agent (deterministic) | 1.0000 | 1.0000 | 1.0000 | 0.9750 | 1.0000 |

What the extra context signals buy, case by case:

- callback-verification flows that look public-facing but still need SSRF review
- open-redirect broker probes that only land on localhost after the first hop
- broader repair coverage, especially DNS pinning, redirect validation, timeout caps

## Project layout

- `src/ssrf_defense_lab/scenarios.py` - the 14 synthetic SSRF and benign fetch scenarios
- `src/ssrf_defense_lab/baseline.py` - traditional rule-based defender
- `src/ssrf_defense_lab/agent.py` - deterministic context-aware defender (wraps the baseline)
- `src/ssrf_defense_lab/training.py` - JSONL training export for fine-tuning or regression sets
- `src/ssrf_defense_lab/benchmark.py` - metrics, comparison, and report generation
- `scripts/train_benchmark.py` - one-shot entry point to regenerate artifacts
- `reports/` - generated human-readable and JSON evaluations (gitignored)
- `data/ssrf_defense_training.jsonl` - generated training corpus

## Run it

```bash
python3 scripts/train_benchmark.py
python3 -m unittest discover -s tests
```

## How the evaluation works

1. Each scenario encodes framework context, route purpose, outbound client, URL target,
   redirect behavior, DNS outcome, and expected defender action.
2. The traditional baseline applies mostly static SSRF rules such as scheme denial,
   private-address blocking, and redirect suspicion.
3. The context-aware defender adds reasoning over fetch surface, allowlist presence,
   tenant risk, nested redirect targets, and repair selection — on top of the baseline's
   verdict, never replacing it.
4. The benchmark compares unsafe detection, exact action choice, block recall, repair
   coverage, and per-framework adaptability.

## Notes

- This repository stays on the defensive side: it models SSRF risk signals and
  remediation strategies rather than shipping exploit automation.
- The defender is deterministic so it can be regression-tested offline with no network
  and no API key. If you swap in a live model adapter, note that `reports/` is
  gitignored — provider responses and error strings must not be committed.
