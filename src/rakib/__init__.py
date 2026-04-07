"""Rakib — Data flow security for AI agents.

Tracks the provenance of every value through agent tool calls.
Prevents untrusted data (web scrapes, external APIs) from controlling
agent actions (message routing, code commits, task delegation).

Based on Google DeepMind CaMeL + Microsoft Dromedary.
Portable: all rules in config/OPA, zero hardcoded tool names.
"""

from rakib.executor import SecureExecutor, PolicyViolation
from rakib.provenance import ProvenanceTracker, ProvenanceGraph
from rakib.policy import PolicyEngine, PolicyConfig, PolicyDecision

__version__ = "0.1.2"
__all__ = [
    "SecureExecutor",
    "PolicyViolation",
    "ProvenanceTracker",
    "ProvenanceGraph",
    "PolicyEngine",
    "PolicyConfig",
    "PolicyDecision",
]
