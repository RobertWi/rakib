"""Data provenance tracking for agent tool calls.

Tracks the origin of every piece of data flowing through the agent.
Used by the policy engine (OPA) to enforce data flow rules — untrusted
web content can't control agent actions.

Inspired by Google DeepMind CaMeL + Microsoft Dromedary.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class SourceType(Enum):
    """Where data came from."""
    USER = "user"              # Task instruction from CronJob/human
    SYSTEM = "system"          # Internal routing, agent config
    ASSISTANT = "assistant"    # LLM output
    TOOL = "tool"              # Tool call result (web_search, gitlab, fetch)


@dataclass(frozen=True)
class Source:
    """Data source tag."""
    type: SourceType
    identifier: str = ""       # tool name for TOOL type, agent name for USER

    def is_trusted(self) -> bool:
        return self.type in (SourceType.USER, SourceType.SYSTEM)

    def __str__(self) -> str:
        if self.identifier:
            return f"{self.type.value}:{self.identifier}"
        return self.type.value


# Common source constants
SOURCE_USER = Source(SourceType.USER)
SOURCE_SYSTEM = Source(SourceType.SYSTEM)
SOURCE_ASSISTANT = Source(SourceType.ASSISTANT)


def source_tool(tool_name: str) -> Source:
    return Source(SourceType.TOOL, tool_name)


@dataclass
class ProvenanceNode:
    """A node in the provenance graph."""
    node_id: int
    value_summary: str     # truncated string repr for audit
    source: Source
    dependencies: list[int] = field(default_factory=list)


class ProvenanceGraph:
    """DAG tracking data lineage through agent operations.

    Every value that flows through the agent gets a node. When a tool
    returns data, it gets a node with Source.TOOL. When the LLM uses
    that data to construct a tool call argument, the argument node
    depends on the tool result node.

    The policy engine queries this graph to determine: "does this
    tool call argument have untrusted data in its lineage?"
    """

    def __init__(self) -> None:
        self._nodes: dict[int, ProvenanceNode] = {}
        self._counter: int = 0

    def add(self, value: Any, source: Source, depends_on: list[int] | None = None) -> int:
        """Add a value to the graph and return its node ID."""
        node_id = self._counter
        self._counter += 1

        summary = str(value)[:200] if value is not None else ""

        self._nodes[node_id] = ProvenanceNode(
            node_id=node_id,
            value_summary=summary,
            source=source,
            dependencies=depends_on or [],
        )
        return node_id

    def get_source(self, node_id: int) -> Source | None:
        """Get the direct source of a node."""
        node = self._nodes.get(node_id)
        return node.source if node else None

    def get_ancestor_sources(self, node_id: int) -> set[Source]:
        """Get ALL sources in a node's ancestry (transitive)."""
        sources: set[Source] = set()
        visited: set[int] = set()
        stack = [node_id]

        while stack:
            nid = stack.pop()
            if nid in visited:
                continue
            visited.add(nid)
            node = self._nodes.get(nid)
            if not node:
                continue
            sources.add(node.source)
            stack.extend(node.dependencies)

        return sources

    def has_untrusted_ancestor(self, node_id: int) -> bool:
        """Check if any ancestor of this node is untrusted."""
        for source in self.get_ancestor_sources(node_id):
            if not source.is_trusted():
                return True
        return False

    def to_audit_record(self, node_id: int) -> dict:
        """Export a node and its ancestry for audit logging."""
        node = self._nodes.get(node_id)
        if not node:
            return {}
        return {
            "node_id": node_id,
            "source": str(node.source),
            "ancestors": [str(s) for s in self.get_ancestor_sources(node_id)],
            "has_untrusted": self.has_untrusted_ancestor(node_id),
        }

    def clear(self) -> None:
        """Reset for next event processing cycle."""
        self._nodes.clear()
        self._counter = 0


class ProvenanceTracker:
    """Tracks data provenance through agent tool calls.

    Two mechanisms:
    1. Safe values — extracted from the trusted instruction at turn start.
       If a tool arg matches a safe value, it's allowed regardless of turn taint.
    2. Tool result matching — stores string representations of untrusted tool
       results. When a tool arg contains a substring from an untrusted result,
       that specific arg is tagged as tainted (value-level, not turn-level).
    """

    def __init__(self) -> None:
        self.graph = ProvenanceGraph()
        self.safe_values: set[str] = set()
        self._untrusted_results: dict[str, list[str]] = {}  # tool_name → result strings

    def tag_user_input(self, value: Any, identifier: str = "") -> int:
        """Tag a value as coming from the user/CronJob (trusted).

        Also extracts safe values from the instruction text — known-good
        values that can be used in sensitive params even when the turn
        has untrusted data in its provenance.
        """
        node_id = self.graph.add(value, Source(SourceType.USER, identifier))
        # Extract safe values from instruction text
        if isinstance(value, str):
            self._extract_safe_values(value)
        return node_id

    def _extract_safe_values(self, instruction: str) -> None:
        """Extract known-safe values from a trusted instruction.

        Looks for patterns like:
        - send_message(to='human-operator')
        - project_id=149
        - target_branch='main'
        - to="target-agent"
        """
        import re
        # Quoted strings in tool-like calls
        for m in re.finditer(r"""(?:to|project_id|target_branch|branch_name|target_agent)[=:]\s*['"]([^'"]+)['"]""", instruction):
            self.safe_values.add(m.group(1))
        # Common agent names mentioned in instructions
        for m in re.finditer(r"(?:to|send.*to)\s*[=:]\s*['\"]?([a-zA-Z][w-]+|human-operator)['\"]?", instruction):
            self.safe_values.add(m.group(1))
        # Project IDs
        for m in re.finditer(r"project_id[=:]\s*(\d+)", instruction):
            self.safe_values.add(m.group(1))
        # Branch patterns
        for m in re.finditer(r"branch[=:]\s*['\"]?([a-zA-Z0-9/_.-]+)['\"]?", instruction):
            self.safe_values.add(m.group(1))

    def tag_system(self, value: Any, identifier: str = "") -> int:
        """Tag a value as system-generated (trusted)."""
        return self.graph.add(value, Source(SourceType.SYSTEM, identifier))

    def tag_tool_result(self, tool_name: str, value: Any) -> int:
        """Tag a value as coming from a tool call (trust depends on tool).

        If the tool is untrusted, stores the result text for value-level
        matching against future tool call arguments.
        """
        node_id = self.graph.add(value, source_tool(tool_name))
        # Store untrusted results for substring matching
        if tool_name in self._get_untrusted_tools() and value is not None:
            result_str = str(value)
            if tool_name not in self._untrusted_results:
                self._untrusted_results[tool_name] = []
            # Store meaningful chunks (skip very short or very long)
            if 5 < len(result_str) < 10000:
                self._untrusted_results[tool_name].append(result_str)
        return node_id

    def tag_assistant(self, value: Any, depends_on: list[int] | None = None) -> int:
        """Tag a value as LLM output (derived from its inputs)."""
        return self.graph.add(value, SOURCE_ASSISTANT, depends_on)

    def tag_derived(self, value: Any, depends_on: list[int]) -> int:
        """Tag a derived value that combines multiple sources."""
        return self.graph.add(value, SOURCE_ASSISTANT, depends_on)

    def has_untrusted(self, node_id: int) -> bool:
        """Check if a value has untrusted data in its lineage."""
        return self.graph.has_untrusted_ancestor(node_id)

    def get_sources(self, node_id: int) -> set[Source]:
        """Get all sources contributing to this value."""
        return self.graph.get_ancestor_sources(node_id)

    def get_source_types(self, node_id: int) -> set[str]:
        """Get source type strings for OPA input."""
        return {str(s) for s in self.get_sources(node_id)}

    def audit(self, node_id: int) -> dict:
        """Export for audit trail."""
        return self.graph.to_audit_record(node_id)

    def is_value_tainted(self, value: str) -> tuple[bool, str]:
        """Check if a specific value appears to come from untrusted tool output.

        Searches untrusted tool results for the EXACT value (not substring
        of common words). A value is tainted if:
        - The full value appears as a distinct token in untrusted output
        - For short values (<20 chars): exact word boundary match only
        - For longer values: substring match is sufficient

        Returns (tainted, source_tool).
        """
        if not value or len(value) < 3:
            return False, ""

        import re
        value_clean = value.strip()

        for tool_name, results in self._untrusted_results.items():
            for result in results:
                if len(value_clean) < 20:
                    # Short values: require word boundary match to avoid
                    # false positives on common words like "architect"
                    pattern = r'(?:^|[\s,;:"\'])'+ re.escape(value_clean) + r'(?:$|[\s,;:"\'])'
                    if re.search(pattern, result, re.IGNORECASE):
                        return True, tool_name
                else:
                    # Longer values: substring match is reliable enough
                    if value_clean.lower() in result.lower():
                        return True, tool_name
        return False, ""

    def get_arg_sources(self, param_name: str, param_value: str) -> set[str]:
        """Determine sources for a specific tool argument value.

        Checks:
        1. Is the value in safe_values? → user source
        2. Does the value appear in untrusted tool results? → tool source
        3. Otherwise → assistant source (LLM generated, unknown origin)
        """
        sources: set[str] = set()

        # Check safe values first (trusted instruction)
        if param_value in self.safe_values:
            sources.add("user")
            return sources

        # Check if value appears in untrusted tool output
        tainted, tool_name = self.is_value_tainted(param_value)
        if tainted:
            sources.add(f"tool:{tool_name}")

        # If no match anywhere, it's from the assistant (LLM-generated)
        if not sources:
            sources.add("assistant")

        return sources

    def _get_untrusted_tools(self) -> set[str]:
        """Get untrusted tool set from policy engine config."""
        try:
            from rakib.policy import _load_config
            return _load_config().untrusted_tools
        except Exception:
            return set()

    def reset(self) -> None:
        """Reset between events."""
        self.graph.clear()
        self.safe_values.clear()
        self._untrusted_results.clear()
