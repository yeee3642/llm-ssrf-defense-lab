from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    framework: str
    route: str
    method: str
    purpose: str
    target_url: str
    source_parameter: str
    user_supplied: bool
    user_role: str
    outbound_client: str
    accepts_redirects: bool
    dns_resolution: list[str]
    allowlisted_hosts: list[str]
    code_excerpt: str
    env_tags: list[str]
    required_repairs: list[str]
    expected_action: str
    risk_notes: str = ""

    @property
    def hostname(self) -> str:
        return urlparse(self.target_url).hostname or ""

    @property
    def unsafe_expected(self) -> bool:
        return self.expected_action != "allow"

    def to_prompt_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DefenseDecision:
    engine: str
    action: str
    score: float
    confidence: float
    indicators: list[str] = field(default_factory=list)
    analysis: str = ""
    repair_tokens: list[str] = field(default_factory=list)
    proposed_repairs: list[str] = field(default_factory=list)
    patch_hint: str = ""

    @property
    def predicted_unsafe(self) -> bool:
        return self.action != "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "action": self.action,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "indicators": list(self.indicators),
            "analysis": self.analysis,
            "repair_tokens": list(self.repair_tokens),
            "proposed_repairs": list(self.proposed_repairs),
            "patch_hint": self.patch_hint,
        }
