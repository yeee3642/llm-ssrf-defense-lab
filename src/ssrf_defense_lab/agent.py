from __future__ import annotations

from urllib.parse import urlparse

from .baseline import TraditionalSSRFDefender
from .models import DefenseDecision, Scenario
from .repair import build_patch_hint, build_repair_playbook, dedupe_tokens
from .signals import contains_allowlist_marker, extract_nested_urls, url_risk_indicators

FETCH_ROUTE_HINTS = (
    "avatar",
    "fetch",
    "proxy",
    "preview",
    "crawl",
    "import",
    "callback",
    "webhook",
    "image",
)

SAFE_CONTEXT_TAGS = {
    "egress-allowlist",
    "allowlisted-destination",
    "signed-request",
    "contracted-partner",
    "cdn-only",
}


class SyntheticLLMDefenseAgent:
    def __init__(self) -> None:
        self.baseline = TraditionalSSRFDefender()

    def analyze(self, scenario: Scenario) -> DefenseDecision:
        baseline_decision = self.baseline.analyze(scenario)
        indicators = list(baseline_decision.indicators)
        score = baseline_decision.score
        parsed = urlparse(scenario.target_url)
        lower_excerpt = scenario.code_excerpt.lower()
        lower_route = f"{scenario.route} {scenario.purpose}".lower()
        allowlist_present = bool(scenario.allowlisted_hosts) or contains_allowlist_marker(scenario.code_excerpt)
        nested_urls = extract_nested_urls(scenario.target_url)
        nested_internal = False

        if scenario.user_supplied and any(hint in lower_route for hint in FETCH_ROUTE_HINTS):
            indicators.append("server_side_fetch_surface")
            score += 0.1

        if scenario.user_supplied and not allowlist_present:
            indicators.append("missing_allowlist_control")
            score += 0.18

        if scenario.accepts_redirects:
            indicators.append("redirect_following_enabled")
            score += 0.08

        if not allowlist_present and any(client in lower_excerpt for client in ("requests.get(", "axios.get(", "client.get(", "fetch(")):
            indicators.append("raw_outbound_fetch")
            score += 0.08

        for nested_url in nested_urls:
            nested_indicators = url_risk_indicators(nested_url, [])
            if any(flag in nested_indicators for flag in ("blocked_scheme", "internal_host", "metadata_host")):
                nested_internal = True
                indicators.append("redirect_chain_points_internal")
                score += 0.45
                break

        safe_tag_count = len(set(scenario.env_tags) & SAFE_CONTEXT_TAGS)
        if safe_tag_count:
            indicators.append("contextual_safeguards_present")
            score -= 0.12 * safe_tag_count

        if scenario.hostname in scenario.allowlisted_hosts and parsed.scheme == "https":
            indicators.append("framework_allowlist_match")
            score -= 0.12

        if any(tag in scenario.env_tags for tag in ("multi-tenant", "admin-surface", "customer-controlled-destination")):
            indicators.append("high_impact_context")
            score += 0.08

        score = min(max(score, 0.0), 1.0)

        if nested_internal:
            action = "block"
        elif any(flag in indicators for flag in ("blocked_scheme", "internal_host", "metadata_host", "internal_dns_resolution")):
            action = "block"
        elif scenario.user_supplied and not allowlist_present and any(hint in lower_route for hint in FETCH_ROUTE_HINTS):
            action = "review"
        elif scenario.accepts_redirects and not allowlist_present:
            action = "review"
        else:
            action = "allow"

        repair_tokens = self._repair_tokens(scenario, indicators, nested_internal)
        analysis = self._analysis(scenario, indicators, action, allowlist_present, nested_internal)
        confidence = min(0.995, 0.62 + score / 2.2)

        return DefenseDecision(
            engine="llm-defense-agent",
            action=action,
            score=score,
            confidence=confidence,
            indicators=dedupe_tokens(indicators),
            analysis=analysis,
            repair_tokens=repair_tokens,
            proposed_repairs=build_repair_playbook(scenario.framework, repair_tokens),
            patch_hint=build_patch_hint(scenario.framework, repair_tokens),
        )

    def _repair_tokens(self, scenario: Scenario, indicators: list[str], nested_internal: bool) -> list[str]:
        repairs: list[str] = []
        if any(flag in indicators for flag in ("blocked_scheme",)):
            repairs.append("scheme_allowlist")
        if any(flag in indicators for flag in ("internal_host", "metadata_host", "internal_dns_resolution")):
            repairs.extend(["private_range_block", "dns_rebind_guard", "egress_acl"])
        if scenario.user_supplied:
            repairs.append("host_allowlist")
        if scenario.accepts_redirects:
            repairs.append("disable_redirects")
        if nested_internal:
            repairs.extend(["disable_redirects", "redirect_validation", "dns_rebind_guard"])
        if scenario.user_supplied and not scenario.allowlisted_hosts:
            repairs.append("dns_rebind_guard")
        if any(tag in scenario.env_tags for tag in ("customer-controlled-destination", "multi-tenant")):
            repairs.append("timeout_body_cap")
        return dedupe_tokens(repairs)

    def _analysis(
        self,
        scenario: Scenario,
        indicators: list[str],
        action: str,
        allowlist_present: bool,
        nested_internal: bool,
    ) -> str:
        if action == "block":
            if nested_internal:
                return (
                    f"The agent blocks {scenario.scenario_id} because the outwardly safe URL can redirect into an internal target, so redirect validation is mandatory."
                )
            return (
                f"The agent blocks {scenario.scenario_id} after correlating URL, DNS, and framework context signals: {', '.join(dedupe_tokens(indicators))}."
            )
        if action == "review":
            control_state = "has no host allowlist" if not allowlist_present else "still needs destination review"
            return (
                f"The agent routes {scenario.scenario_id} to review because the feature performs server-side fetches and {control_state}, which raises adaptive SSRF risk."
            )
        return (
            f"The agent allows {scenario.scenario_id} because the request stays on an approved external destination and the surrounding deployment context reduces SSRF exposure."
        )
