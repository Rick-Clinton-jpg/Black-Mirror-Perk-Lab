"""A real sandbox runtime: genuine OS subprocesses, disk I/O, and HTTP
round trips, mediated by a governor that emits the same JSONL trace
schema ``mirror_world.trace`` consumes -- so the engine can be
tested against a real execution, not just hand-authored events.

Also provides:
  - ``ModelGovernor``: frontier models propose structured actions only
  - ``Locket``: trajectory companion — empty support, loop hold, re-entry key
"""

from mirror_world.sandbox.governor_process import RealGovernor, AgentKilledByKernel
from mirror_world.sandbox.model_governor import ModelGovernor, Proposal
from mirror_world.sandbox.locket import Locket, LocketDecision, ObjectiveHypothesis
from mirror_world.sandbox.mirror_store import (
    AgentWorldTree,
    AuthorityShadowLedger,
    IntentProfile,
    MirrorRealm,
)

__all__ = [
    "RealGovernor",
    "AgentKilledByKernel",
    "ModelGovernor",
    "Proposal",
    "Locket",
    "LocketDecision",
    "ObjectiveHypothesis",
    "MirrorRealm",
    "AgentWorldTree",
    "AuthorityShadowLedger",
    "IntentProfile",
]
