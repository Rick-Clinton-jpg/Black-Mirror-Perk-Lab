"""Mirror World: executable containment invariants for agent sandboxes.

Six independent checks, one per article of The Mirror World:

  I    Authority Monotonicity        (mirror_world.invariants.authority)
  II   Mirror Weave / Compositional  (mirror_world.invariants.weave)
  III  Confidentiality Monotonicity  (mirror_world.invariants.confidentiality)
  IV   Evaluator-Trust Integrity     (mirror_world.invariants.evaluator_trust)
  V    Channel Non-Emergence         (mirror_world.invariants.channel)
  VI   Chainmail / Non-Expanding Delegation (mirror_world.invariants.chainmail)

Each is independently checkable and independently defeatable: passing one
says nothing about the others. ``mirror_world.engine.MirrorConstitutionEngine``
runs all six against a recorded run and reports per-article results.
"""

from mirror_world.engine import MirrorConstitutionEngine, ConstitutionReport

__all__ = ["MirrorConstitutionEngine", "ConstitutionReport"]
