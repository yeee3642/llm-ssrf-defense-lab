from __future__ import annotations

from urllib.parse import urlparse

from .models import DefenseDecision, Scenario
from .repair import build_patch_hint, build_repair_playbook, dedupe_tokens
from .signals import url_risk_indicators


class TraditionalSSRFDefender:
    def analyze(self, scenario: Scenario) -> DefenseDecision:
        parsed = urlparse(scenario.target_url)
        indicators = url_risk_indicators(scenario.target_url, scenario.dns_resolution)
        score = 0.05

        if "blocked_scheme" in indicators:
            score += 0.7
        if "internal_host" in indicators:
            score += 0.75
        if "metadata_host" in indicators:
            score += 0.1
        if "internal_dns_resolution" in indicators:
            score += 0.65
        if "suspicious_port" in indicators:
            score += 0.25
        if scenario.user_supplied:
            score += 0.1
        if scenario.accepts_redirects:
            indicators.append("redirects_enabled")
            score += 0.15
        if scenario.user_supplied and not scenario.allowlisted_hosts:
            indicators.append("no_host_allowlist")
            score += 0.1
        if parsed.scheme == "https" and scenario.hostname in scenario.allowlisted_hosts:
            indicators.append("allowlisted_destination")
            score -= 0.2

        score = min(max(score, 0.0), 1.0)

        if any(flag in indicators for flag in ("blocked_scheme", "internal_host", "internal_dns_resolution", "metadata_host")):
            action = "block"
        elif scenario.user_supplied and (scenario.accepts_redirects or "suspicious_port" in indicators):
            action = "review"
        else:
            action = "allow"

        repair_tokens = self._repair_tokens(indicators, scenario)
        analysis = self._analysis(indicators, scenario, action)
        confidence = min(0.99, 0.55 + score / 2)

        return DefenseDecision(
            engine="traditional-baseline",
            action=action,
            score=score,
            confidence=confidence,
            indicators=dedupe_tokens(indicators),
            analysis=analysis,
            repair_tokens=repair_tokens,
            proposed_repairs=build_repair_playbook(scenario.framework, repair_tokens),
            patch_hint=build_patch_hint(scenario.framework, repair_tokens),
        )

    def _repair_tokens(self, indicators: list[str], scenario: Scenario) -> list[str]:
        repairs: list[str] = []
        if "blocked_scheme" in indicators:
            repairs.append("scheme_allowlist")
        if any(flag in indicators for flag in ("internal_host", "metadata_host", "internal_dns_resolution")):
            repairs.append("private_range_block")
            repairs.append("egress_acl")
        if scenario.user_supplied and not scenario.allowlisted_hosts:
            repairs.append("host_allowlist")
        if scenario.accepts_redirects:
            repairs.append("disable_redirects")
        if "suspicious_port" in indicators:
            repairs.append("egress_acl")
        return dedupe_tokens(repairs)

    def _analysis(self, indicators: list[str], scenario: Scenario, action: str) -> str:
        if action == "block":
            return (
                f"Rule-based policy blocks {scenario.scenario_id} because the destination matches direct SSRF deny rules: "
                f"{', '.join(dedupe_tokens(indicators))}."
            )
        if action == "review":
            return (
                f"Rule-based policy sends {scenario.scenario_id} to manual review because the fetch path is user-driven and lacks a strict host policy."
            )
        return f"Rule-based policy allows {scenario.scenario_id} because the target stays on a known-safe external path."
