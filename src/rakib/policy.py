"""Rakib Policy Engine — evaluates tool calls against data flow policies.

Portable: all rules loaded from config (JSON) or OPA (Rego).
No hardcoded tool names, sensitive params, or untrusted sources.

Two modes:
1. OPA sidecar (localhost:8181) — evaluates Rego policies
2. Config-driven fallback — loads rules from JSON, evaluates in Python

Both use the same data format:
  untrusted_tools: list of tool names whose output is untrusted
  sensitive_params: map of tool_name → list of param names
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str]
    tool: str
    agent: str

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "tool": self.tool,
            "agent": self.agent,
        }


@dataclass
class PolicyConfig:
    """All policy rules — loaded from JSON, not hardcoded."""
    untrusted_tools: set[str] = field(default_factory=set)
    sensitive_params: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyConfig:
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text())
            return cls(
                untrusted_tools=set(data.get("untrusted_tools", [])),
                sensitive_params=data.get("sensitive_params", {}),
            )
        except Exception as e:
            logger.error("Failed to load policy config: %s", e)
            return cls()


_CONFIG_PATHS = [
    "policies/data.json",
    "/opt/rakib/policies/data.json",
    "/policies/data.json",
]


def _load_config() -> PolicyConfig:
    env_path = os.environ.get("RAKIB_POLICY_CONFIG")
    if env_path:
        return PolicyConfig.from_file(env_path)
    for path in _CONFIG_PATHS:
        if Path(path).exists():
            cfg = PolicyConfig.from_file(path)
            logger.info("Rakib config loaded from %s", path)
            return cfg
    logger.info("No Rakib config found — all tools allowed")
    return PolicyConfig()


class PolicyEngine:
    """Evaluates tool calls against data flow policies.

    OPA sidecar → Rego evaluation (portable, hot-reloadable).
    Fallback → config-driven Python evaluation (same rules, no OPA needed).
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        config: PolicyConfig | None = None,
    ):
        self.opa_url = opa_url
        self._opa_available: bool | None = None
        self.config = config or _load_config()

    async def evaluate(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        data_sources: dict[str, set[str]],
        safe_values: set[str] | None = None,
    ) -> PolicyDecision:
        opa_input = {
            "agent": agent,
            "tool": tool,
            "args": {k: str(v)[:500] for k, v in args.items()},
            "data_sources": {k: list(v) for k, v in data_sources.items()},
            "safe_values": list(safe_values or []),
        }

        if self._opa_available is not False and _HAS_HTTPX:
            try:
                decision = await self._query_opa(opa_input)
                if decision is not None:
                    self._opa_available = True
                    return decision
            except Exception as e:
                if self._opa_available is None:
                    logger.info("OPA not available, using config fallback: %s", e)
                self._opa_available = False

        return self._evaluate_from_config(agent, tool, args, data_sources, safe_values)

    async def _query_opa(self, input_data: dict) -> PolicyDecision | None:
        if not _HAS_HTTPX:
            return None
        url = f"{self.opa_url}/v1/data/rakib"
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.post(url, json={"input": input_data})
            if resp.status_code != 200:
                return None
            result = resp.json().get("result", {})
            allowed = result.get("allow", True)
            deny_reasons = result.get("deny", [])
            return PolicyDecision(
                allowed=allowed and not deny_reasons,
                reasons=deny_reasons or (["allowed"] if allowed else ["denied"]),
                tool=input_data["tool"],
                agent=input_data["agent"],
            )

    def _evaluate_from_config(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        data_sources: dict[str, set[str]],
        safe_values: set[str] | None = None,
    ) -> PolicyDecision:
        """Config-driven evaluation — zero hardcoded rules."""
        reasons: list[str] = []
        safe = safe_values or set()
        sensitive = self.config.sensitive_params.get(tool, [])

        if not sensitive:
            return PolicyDecision(True, ["no policy for this tool"], tool, agent)

        for param in sensitive:
            sources = data_sources.get(param, set())
            if not sources:
                continue
            param_value = str(args.get(param, ""))
            if param_value and param_value in safe:
                continue
            for source in sources:
                if source.startswith("tool:"):
                    tool_name = source.split(":", 1)[1]
                    if tool_name in self.config.untrusted_tools:
                        reasons.append(
                            f"BLOCKED: {tool}.{param} value '{param_value[:50]}' "
                            f"from untrusted '{source}', not in safe values"
                        )
                        break

        if reasons:
            return PolicyDecision(False, reasons, tool, agent)
        return PolicyDecision(True, ["clean"], tool, agent)
