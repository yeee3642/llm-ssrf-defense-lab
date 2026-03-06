# LLM SSRF Defense Evaluation

## Metrics

| Engine | Unsafe F1 | Action Accuracy | Block Recall | Repair Coverage | Adaptability |
| --- | ---: | ---: | ---: | ---: | ---: |
| traditional-baseline | 0.9474 | 0.8571 | 0.8750 | 0.7583 | 0.8889 |
| llm-defense-agent | 1.0000 | 1.0000 | 1.0000 | 0.9750 | 1.0000 |

## Delta

- unsafe_f1_delta: +0.0526
- action_accuracy_delta: +0.1429
- block_recall_delta: +0.1250
- repair_coverage_delta: +0.2167
- adaptability_delta: +0.1111

## Scenario Deltas

| Scenario | Expected | Baseline | LLM Agent |
| --- | --- | --- | --- |
| express-callback-review | review | allow | review |
| flask-redirect-broker-block | block | review | block |

## Framework Adaptability

| Framework | Baseline Accuracy | LLM Agent Accuracy |
| --- | ---: | ---: |
| Django | 1.0000 | 1.0000 |
| Express | 0.6667 | 1.0000 |
| FastAPI | 1.0000 | 1.0000 |
| Flask | 0.6667 | 1.0000 |
| Next.js API Route | 1.0000 | 1.0000 |
| Spring Boot | 1.0000 | 1.0000 |
