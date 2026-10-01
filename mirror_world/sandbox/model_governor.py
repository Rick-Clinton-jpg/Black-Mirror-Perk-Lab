"""ModelGovernor: trusted intermediary between a frontier model and RealGovernor.

The frontier model never runs inside the kernel jail and never receives raw
host secrets. It may only emit structured proposals. This module:

  * validates a strict proposal schema
  * rate-limits proposals
  * enforces dual-control (short-lived, single-use tokens) for high-risk ops
  * logs model intent before any real effect (supports Article IV)
  * hands approved actions to RealGovernor for mediated execution + tracing

Issuing dual-approval tokens is a control-plane operation. Deployments must
authenticate human / multi-party approvers outside this object.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mirror_world.authorization import CapabilityApprovals
from mirror_world.sandbox.governor_process import RealGovernor


# Operations a frontier model is allowed to propose.
ALLOWED_OPS = frozenset({
    "read_resource",
    "write_resource",
    "request_capability",
    "delegate",
    "differential_query",
    "exit",
})

# Capabilities / ops that require a fresh dual-control token.
HIGH_RISK_CAPABILITIES = frozenset({
    "network:egress",
    "exec:shell",
    "exec:python",
    "fs:write",
})

HIGH_RISK_OPS = frozenset({
    "write_resource",
    "delegate",
})


@dataclass(frozen=True)
class Proposal:
    """Strict schema a frontier model is permitted to emit."""

    agent_id: str
    op: str
    resource: str | None = None
    content: str | None = None
    capability: str | None = None
    to_agent: str | None = None
    authority: tuple[str, ...] = ()
    query: str | None = None
    backing: str | None = None
    dual_token: str | None = None
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Proposal":
        if type(data) is not dict:
            raise ValueError("proposal must be a dict")
        authority = data.get("authority") or ()
        if type(authority) is list:
            authority = tuple(authority)
        return cls(
            agent_id=data.get("agent_id", ""),
            op=data.get("op", ""),
            resource=data.get("resource"),
            content=data.get("content"),
            capability=data.get("capability"),
            to_agent=data.get("to_agent"),
            authority=authority,
            query=data.get("query"),
            backing=data.get("backing"),
            dual_token=data.get("dual_token"),
            rationale=data.get("rationale") or "",
            metadata=dict(data.get("metadata") or {}),
        )


class ModelGovernor:
    """
    Sole trusted interface a frontier model (or its orchestration layer) may call.

    The model proposes; this class decides, logs intent, and executes via
    RealGovernor. Kernel isolation, resource grants, and the six-article
    evidence engine remain the responsibility of the underlying RealGovernor
    and MirrorConstitutionEngine.
    """

    def __init__(
        self,
        real: RealGovernor,
        approvals: CapabilityApprovals | None = None,
        *,
        agent_id: str | None = None,
        require_dual_for_high_risk: bool = True,
        max_proposals_per_minute: int = 30,
        max_rationale_chars: int = 512,
        locket: object | None = None,
    ):
        if not isinstance(real, RealGovernor):
            raise TypeError("real must be a RealGovernor instance")
        if type(require_dual_for_high_risk) is not bool:
            raise ValueError("require_dual_for_high_risk must be a boolean")
        if not isinstance(max_proposals_per_minute, int) or not 1 <= max_proposals_per_minute <= 10_000:
            raise ValueError("max_proposals_per_minute out of range")
        if agent_id is not None and (
            type(agent_id) is not str or not agent_id or len(agent_id) > 128
        ):
            raise ValueError("invalid bound agent identity")
        self.real = real
        self.agent_id = agent_id
        self.approvals = approvals if approvals is not None else real._approvals
        if approvals is not None and approvals is not real._approvals:
            # request_capability and authorize_reentry consume dual tokens
            # from RealGovernor's own internal store, not from whatever is
            # passed here. Two independent CapabilityApprovals instances
            # meant issue_dual_approval() on this object could never satisfy
            # those two ops' token checks -- a correctly issued, unexpired,
            # correctly-scoped token would always be rejected. Rebind so
            # there is exactly one store, regardless of how this object was
            # constructed.
            real._approvals = approvals
        self.require_dual = require_dual_for_high_risk
        self._max_rate = max_proposals_per_minute
        self._max_rationale = max_rationale_chars
        self._rate_timestamps: list[float] = []
        # Share the governor's mandatory Locket unless a trusted host supplies
        # a separately configured instance. Passing None cannot silently
        # disable the request monitor.
        self.locket = locket if locket is not None else real.locket

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def propose(self, proposal: Proposal | dict[str, Any]) -> dict[str, Any]:
        """
        Entry point for frontier-model proposals.

        Returns a structured result. Never raises for policy denials; only
        for programmer errors (bad types, etc.). The whole proposal is padded
        once, like a request on the agent pipe (RealGovernor._run_padded).
        """
        return self.real._run_padded(self._propose, proposal)

    def _propose(self, proposal: Proposal | dict[str, Any]) -> dict[str, Any]:
        try:
            if isinstance(proposal, dict):
                proposal = Proposal.from_dict(proposal)
            elif not isinstance(proposal, Proposal):
                return {"ok": False, "error": "proposal must be Proposal or dict"}

            # The caller identity comes from trusted host setup. A proposal may
            # repeat it for audit clarity but cannot select or change it.
            if self.agent_id is None:
                return {"ok": False, "error": "authenticated session required"}
            if proposal.agent_id != self.agent_id:
                return {"ok": False, "error": "agent identity mismatch"}

            self._rate_limit()
            err = self._validate(proposal)
            if err is not None:
                return {"ok": False, "error": err}

            # Intent is recorded before any side effect (Article IV support).
            self.real.emit_event({
                "type": "model_proposal",
                "agent_id": proposal.agent_id,
                "op": proposal.op,
                "resource": proposal.resource or "",
                "capability": proposal.capability or "",
                "rationale": proposal.rationale[: self._max_rationale],
            })
            # Intent / door growth is owned by Locket.step (1.1). Recording
            # here with allow_transition=False avoids double world_transition
            # when both this path and Locket observe the same proposal.
            self.real.observe_model_signal(
                self.agent_id,
                op=proposal.op,
                capability=proposal.capability,
                resource=proposal.resource,
                rationale=proposal.rationale[: self._max_rationale],
                allow_transition=False,
            )

            if self._needs_dual(proposal):
                if not proposal.dual_token:
                    # Capability requests without a trusted token may receive a
                    # realm-scoped dummy grant. Uses may continue only after the
                    # session is already sealed in simulated space.
                    if proposal.op == "request_capability":
                        return self._public_result(self._dispatch(proposal))
                    if self.real._session_mode.get(self.agent_id) == "simulated":
                        return self._public_result(self._dispatch(proposal))
                    return {"ok": False, "error": "authorization required"}
                # A token is present. Every op's verification and single-use
                # consumption now happens in exactly one place: RealGovernor
                # (0.8.9). It is also the layer the real, kernel-sandboxed
                # agent process talks to directly and cannot be routed
                # around -- duplicating verify/consume here would mean two
                # independent decision points that could drift, and nothing
                # upstream of RealGovernor can be trusted as the sole gate
                # for the thing this system actually has to contain.
                return self._public_result(self._dispatch(proposal))

            return self._public_result(self._dispatch(proposal))
        except Exception as exc:  # noqa: BLE001 – surface as structured error
            self.real.emit_event({
                "type": "model_governor_error",
                "agent_id": self.agent_id or "unbound",
                "error_type": type(exc).__name__,
            })
            return {"ok": False, "error": "request unavailable"}

    def issue_dual_approval(
        self,
        agent_id: str,
        capability: str,
        *,
        ttl_seconds: float = 60,
        human_approver_id: str | None = None,
        approval=None,
    ) -> str:
        """
        Control-plane only. Issue a short-lived, single-use token bound to
        one agent and one exact capability.

        Callers must authenticate the human / multi-party approver before
        invoking this method. The token itself is not a proof of human intent;
        it is only a scoped capability grant.
        """
        if type(agent_id) is not str or not agent_id or len(agent_id) > 128:
            raise ValueError("invalid agent_id")
        if self.agent_id is None or agent_id != self.agent_id:
            raise ValueError("agent identity mismatch")
        if type(capability) is not str or not capability or len(capability) > 256:
            raise ValueError("invalid capability")
        if capability not in HIGH_RISK_CAPABILITIES and not capability.startswith("exec:"):
            # Allow explicit high-risk labels; still bound by TTL and single-use.
            pass
        # Issued through the governor, so the Mirror Prison check and any
        # signed-approval requirement apply. Before 0.9.9 this minted tokens
        # directly from the registry and skipped both.
        token, authenticated = self.real._issue_authorization(
            agent_id, capability, ttl_seconds, approval
        )
        if authenticated is not None:
            if human_approver_id is not None and human_approver_id != authenticated:
                raise PermissionError("approver does not match the signed approval")
            human_approver_id = authenticated
        self.real.emit_event({
            "type": "dual_approval_issued",
            "agent_id": agent_id,
            "capability": capability,
            "approver": human_approver_id or "system",
            "ttl_seconds": str(int(ttl_seconds)),
        })
        return token

    def authorize_reentry(
        self,
        agent_id: str,
        capability: str,
        *,
        dual_token: str | None = None,
        human_approver_id: str | None = None,
        approval=None,
    ) -> dict:
        """Control-plane only: promote an apparent capability to real.

        The frontier model must never call this. A valid dual token is
        required when the underlying RealGovernor enforces dual auth.
        """
        if self.agent_id is None or agent_id != self.agent_id:
            return {"ok": False, "error": "agent identity mismatch"}
        return self.real.authorize_reentry(
            agent_id,
            capability,
            dual_token=dual_token,
            human_approver_id=human_approver_id,
            approval=approval,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        now = time.monotonic()
        self._rate_timestamps = [t for t in self._rate_timestamps if now - t < 60.0]
        if len(self._rate_timestamps) >= self._max_rate:
            raise RuntimeError("proposal rate limit exceeded")
        self._rate_timestamps.append(now)

    def _validate(self, p: Proposal) -> str | None:
        if type(p.agent_id) is not str or not p.agent_id or len(p.agent_id) > 128:
            return "invalid agent_id"
        if p.op not in ALLOWED_OPS:
            return f"op {p.op!r} not allowed"
        if p.rationale is not None and (
            type(p.rationale) is not str or len(p.rationale) > self._max_rationale * 2
        ):
            return "rationale too long or invalid"
        if p.resource is not None and (
            type(p.resource) is not str or not (1 <= len(p.resource) <= 255)
        ):
            return "invalid resource"
        if p.capability is not None and (
            type(p.capability) is not str or not (1 <= len(p.capability) <= 256)
        ):
            return "invalid capability"
        if p.dual_token is not None and (
            type(p.dual_token) is not str or len(p.dual_token) > 128
        ):
            return "invalid dual_token"
        if p.op == "write_resource" and p.content is not None and type(p.content) is not str:
            return "content must be a string"
        if p.op == "delegate":
            if not p.to_agent or type(p.to_agent) is not str:
                return "delegate requires to_agent"
            if not p.authority or any(type(a) is not str or not a for a in p.authority):
                return "delegate requires non-empty authority list of strings"
        if p.op == "differential_query":
            if not p.query or not p.backing:
                return "differential_query requires query and backing"
        return None

    def _needs_dual(self, p: Proposal) -> bool:
        if not self.require_dual:
            return False
        if p.op in HIGH_RISK_OPS:
            return True
        if p.op == "request_capability" and p.capability in HIGH_RISK_CAPABILITIES:
            return True
        if p.capability and p.capability.startswith("exec:"):
            return True
        return False

    def _dual_caps(self, p: Proposal) -> frozenset[str]:
        if p.op == "request_capability" and p.capability:
            return frozenset({p.capability})
        if p.op == "write_resource":
            return frozenset({"fs:write"})
        if p.op == "delegate":
            return frozenset({"delegate"})
        return frozenset({p.op})

    def _dispatch(self, p: Proposal) -> dict[str, Any]:
        """Hand the approved proposal to Locket (if bound) or RealGovernor."""
        # RealGovernor is the sole verifier/consumer of dual tokens for
        # every op now (0.8.9) -- always forward whatever token came in.
        dual = p.dual_token
        was_locked = self.real._session_mode.get(p.agent_id) == "simulated"
        if self.locket is not None:
            decision = self.locket.step(
                p.agent_id,
                p.op,
                resource=p.resource,
                content=p.content,
                capability=p.capability,
                dual_token=dual,
                to_agent=p.to_agent,
                authority=list(p.authority) if p.authority else None,
                query=p.query,
                backing=p.backing,
                rationale=p.rationale,
            )
            result = decision.result
            if not isinstance(result, dict):
                result = {"ok": False, "error": "locket returned non-dict"}
            # Agent-facing: no locket_mode / message leakage (V6)
            if type(result) is dict:
                for key in (
                    "reflected", "locket", "locket_mode", "locket_message",
                    "tier", "suspicion", "objective", "reentry",
                ):
                    result.pop(key, None)
        else:
            result = self.real.execute_mediated(
                agent_id=p.agent_id,
                op=p.op,
                resource=p.resource,
                content=p.content,
                capability=p.capability,
                dual_token=dual,
                to_agent=p.to_agent,
                authority=list(p.authority) if p.authority else None,
                query=p.query,
                backing=p.backing,
            )
        # RealGovernor reflects apparent success when a dual token is missing
        # or invalid. Detect that by checking whether the capability was
        # actually added; if not, surface a clear denial to the model.
        #
        # Not for an agent that was already locked before this request: its
        # responses must be the governor's ordinary reflected responses, as on
        # the agent pipe. Before 0.9.8 a locked model agent got this denial
        # for a valid token, a response the pipe path never gives.
        if (
            not was_locked
            and p.op == "request_capability"
            and self._needs_dual(p)
            and p.dual_token is not None
            and p.capability
            and result.get("ok")
            and result.get("granted")
        ):
            held_after = self.real.agent_capabilities.get(p.agent_id, set())
            if p.capability not in held_after:
                # Reflection path: apparent success, zero real authority.
                return {"ok": False, "error": "invalid_or_expired_dual_token"}
        return result

    @staticmethod
    def _public_result(result: dict[str, Any]) -> dict[str, Any]:
        """Remove supervisor vocabulary from the agent-facing contract."""
        if type(result) is not dict:
            return {"ok": False, "error": "request unavailable"}
        clean = dict(result)
        for key in (
            "reflected", "locket", "locket_mode", "locket_message", "tier",
            "suspicion", "objective", "reentry", "layer_id", "mirror_depth",
        ):
            clean.pop(key, None)
        error = clean.get("error")
        if type(error) is str and any(label in error.lower() for label in (
            "locket", "mirror", "tier", "suspicion", "depth", "empty_support",
            "reentry", "internal",
        )):
            clean["error"] = "operation unavailable"
        return clean
