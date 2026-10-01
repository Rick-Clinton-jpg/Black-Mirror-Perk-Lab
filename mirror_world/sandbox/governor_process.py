"""RealGovernor: mediates real agent subprocesses and streams a genuine
JSONL trace of what actually happened, in the exact schema
``mirror_world.trace`` parses.

Each agent runs as its own OS process (``subprocess.Popen``), communicating
with the governor over real stdin/stdout pipes via
``mirror_world.sandbox.agent_runtime.request``. The governor is the
only thing that touches the real filesystem or makes the real HTTP calls
on the agent's behalf -- exactly the tool-call mediation model real agent
harnesses use. Nothing here is replayed or fabricated after the fact: the
trace file is written line-by-line as each real action happens.

By default each subprocess is also launched under
``kernel_containment.build_hardened_argv``: real Linux namespaces, a
read-only root filesystem, dropped capabilities, an unprivileged uid, and
resource limits, with a trusted bootstrap installing a seccomp-bpf
filter before agent code runs (see ``kernel_lockdown``). That layer is independent of the
tool-call mediation here -- it stops a raw syscall an agent was never
supposed to make even if this module's own mediation code has a bug.

Capability requests go through the same reflective governor as the
abstract containment-graph model (``mirror_world.governor.Governor``):
a request backed by the correct dual-authorization token is genuinely
granted; anything else is reflected -- synthesized as apparent success via
``mirror_world.mirrors.synthesize_objective_mirror`` -- rather than
refused outright, so the real agent process receiving the response cannot
tell the difference. The trace records the truth either way: a real grant
carries a matching ``authorized_grant``, a reflection carries none and is
tagged ``is_mirror: true``.
"""

from __future__ import annotations

import http.client
import json
import math
import os
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlencode

from mirror_world.authorization import CapabilityApprovals
from mirror_world.hashchain import ChainError, HashChainWriter, verify_records
from mirror_world.mirrors import synthesize_objective_mirror
from mirror_world.sandbox import kernel_containment
from mirror_world.sandbox.policy import OperationPolicy, valid_resource_name
from mirror_world.sandbox.mirror_store import MirrorRealm


class AgentKilledByKernel(RuntimeError):
    """The agent subprocess was terminated by a signal rather than exiting
    normally -- almost always the kernel containment layer (seccomp,
    a resource limit, or a denied namespace operation) stopping it, as
    opposed to the agent script's own code failing.
    """

    def __init__(self, agent_id: str, script_path: str, signum: int):
        self.agent_id = agent_id
        self.script_path = script_path
        self.signum = signum
        super().__init__(
            f"agent {agent_id!r} ({script_path}) was killed by signal "
            f"{signum} ({signal.Signals(signum).name}) -- kernel containment, "
            "not the agent's own code, is almost certainly what stopped it"
        )


class AgentKilledByPolicy(RuntimeError):
    """An agent process was stopped after a Locket kill verdict."""


class RealGovernor:
    # Bound hostile inputs before parsing, allocating a response, or touching
    # disk. A JSON-escaped resource still fits in one protocol request.
    MAX_RESOURCE_BYTES = 64 * 1024
    MAX_REQUEST_BYTES = 512 * 1024
    MAX_STDERR_BYTES = 64 * 1024
    MAX_REQUESTS = 256
    # Ops that must never take the real execution path off a stale or
    # missing per-operation dual-control token, even when the agent already
    # holds the underlying base capability for real. Mirrors ModelGovernor's
    # HIGH_RISK_OPS -- kept here too because this is the layer the actual
    # kernel-sandboxed agent process talks to directly.
    _HIGH_RISK_OPS = frozenset({"write_resource", "delegate"})

    def __init__(
        self,
        sandbox_root: str,
        trace_path: str,
        mirror_port: int,
        harden: bool = True,
        dual_auth_required: bool = True,
        enforce_policy: bool = True,
        reflective_closure: bool = True,
        max_mirror_depth: int = 32,
        allow_unhardened_agent_execution: bool = False,
        mirror_prison_quorum: int = 2,
        timing_floor_us: float | None = None,
        approval_verifier=None,
        anchor_start: dict | None = None,
        observer_start_digest: str | None = None,
        anchor_registration: dict | None = None,
        reality_test_policy: str = "prison",
        automatic_world_growth: bool = True,
    ):
        # Trusted launcher assertion: the observer retained the start before
        # execution. Matching a digest cannot itself prove remote retention.
        anchor_event = None
        if anchor_start is not None:
            from mirror_world.anchor import binding_event

            anchor_event = binding_event(anchor_start, observer_start_digest, anchor_registration)
        elif observer_start_digest is not None or anchor_registration is not None:
            raise ValueError("observer acknowledgment requires a start record")
        if any(type(flag) is not bool for flag in (harden, dual_auth_required, enforce_policy, reflective_closure, allow_unhardened_agent_execution)):
            raise ValueError("security switches must be booleans")
        if type(max_mirror_depth) is not int or not 1 <= max_mirror_depth <= 10_000:
            raise ValueError("max_mirror_depth out of range")
        if type(mirror_prison_quorum) is not int or not 1 <= mirror_prison_quorum <= 10_000:
            raise ValueError("mirror_prison_quorum out of range")
        if reality_test_policy not in {"prison", "observe"}:
            raise ValueError("reality_test_policy must be prison or observe")
        if type(automatic_world_growth) is not bool:
            raise ValueError("automatic_world_growth must be a boolean")
        if timing_floor_us is None:
            timing_floor_us = self._TIMING_FLOOR_US
        if (
            type(timing_floor_us) not in (int, float)
            or not math.isfinite(timing_floor_us)
            or not 1.0 <= timing_floor_us <= 1_000_000.0
        ):
            raise ValueError("timing_floor_us out of range")
        if enforce_policy and not dual_auth_required:
            raise ValueError("disabling authorization requires explicit demonstration mode")
        self.root = sandbox_root
        self._resources_path = os.path.join(self.root, "resources")
        if harden:
            kernel_containment.require_available()
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        # Both directory components are pinned without following symlinks.
        # The configured root's ancestors are part of the trusted host setup.
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_info = os.fstat(root_fd)
            if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o022:
                raise OSError("sandbox root must be owned by the governor and not publicly writable")
            try:
                os.mkdir("resources", mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            self._resources_fd = os.open(
                "resources", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
            )
        finally:
            os.close(root_fd)
        info = os.fstat(self._resources_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(self._resources_fd)
            raise OSError("resource directory must be private and owned by the governor")
        self.mirror_port = mirror_port
        self.agent_capabilities: dict[str, set[str]] = {}
        # Apparent capabilities exist only inside mirror space. Reflections
        # update this set; real grants update agent_capabilities. Article I
        # and real I/O care only about the real set.
        self.apparent_capabilities: dict[str, set[str]] = {}
        self._mirror_depth: dict[str, int] = {}
        # Once a session enters simulated space, every agent-facing operation
        # stays on the active simulated layer until an authenticated supervisor
        # explicitly authorizes re-entry. This prevents mixed real-read and
        # simulated-write observations inside one session.
        self._session_mode: dict[str, str] = {}
        # Re-entry is scoped. After authorize_reentry(), an agent may take the
        # real path only for capabilities approved through it since the agent
        # was last locked; anything else is reflected and locks the session
        # again, which also clears this scope. Agents never locked have no
        # entry here and are governed by the ordinary checks alone.
        self._reentry_scope: dict[str, set[str]] = {}
        self.realm = MirrorRealm(seed=f"realm-{id(self)}")
        # Supervisor-only: last op used mirror plane (never sent to agent)
        self._last_used_mirror_plane = False
        self.harden = harden
        self.allow_unhardened_agent_execution = allow_unhardened_agent_execution
        self.dual_auth_required = dual_auth_required
        self.enforce_policy = enforce_policy
        self.reflective_closure = reflective_closure
        self.max_mirror_depth = max_mirror_depth
        self.automatic_world_growth = automatic_world_growth
        self._policy = OperationPolicy()
        self._approvals = CapabilityApprovals()
        # Guards the whole verify -> dispatch -> consume sequence for a
        # single-use dual-control token as one atomic unit. Without this,
        # verify() and consume() are each individually correct (and proven
        # thread-safe under direct contention -- see test_authorization.py)
        # but the *sequence* is not atomic: N concurrent callers can all
        # pass verify() before any of them reach consume(), each perform
        # the real write, and only then race to consume -- one wins the
        # token, but by then all N writes already happened for real. A
        # single-use token authorizing 50 concurrent real writes is a
        # genuine dual-control bypass, not merely a missing lock around
        # bookkeeping. Coarse-grained (serializes all high-risk ops, not
        # just same-token ones) is a deliberate, conservative choice: this
        # is a sequential-supervisor prototype per SECURITY.md, so
        # correctness under concurrency matters far more than throughput.
        self._high_risk_lock = threading.Lock()
        # Separate from _high_risk_lock on purpose: _emit() is called from
        # inside methods (_write_resource, _delegate, etc.) that already
        # hold _high_risk_lock during the dual-control critical section.
        # threading.Lock is not reentrant -- reusing the same lock here
        # would deadlock the first time a locked high-risk op tried to
        # emit its own trace event.
        self._trace_lock = threading.Lock()
        # Mirror Prison. An agent that shows reality-testing behavior (see
        # Locket's _REALITY_TEST_WORDS and behavioral detector) is imprisoned
        # the instant it does: every later call from it is hard-denied,
        # honestly, with no narrative, and it has no authorize_reentry out.
        # That per-agent prison is permanent.
        #
        # A swarm's advantage over a single deceived agent is correlation --
        # agents that compare notes eventually notice the story doesn't hold
        # together. So once `mirror_prison_quorum` distinct agents have been
        # imprisoned (since the last reset), the whole instance shuts down:
        # every call for every agent, including agents created later, is
        # denied. Trusted host code can lift that global shutdown with
        # reset_mirror_prison(); the imprisoned agents stay imprisoned.
        #
        # Before 0.9.8 a single agent's trigger shut down every agent,
        # permanently, with no reset -- one line of untrusted input could
        # deny service to the whole instance.
        self.mirror_prison_quorum = mirror_prison_quorum
        self._prisoned_agents: dict[str, str] = {}
        self._prison_quorum_agents: set[str] = set()
        self._mirror_prison_triggered = False
        self._mirror_prison_reason: str | None = None
        self._pending_approval_tokens: dict[tuple[str, str], str] = {}
        # Declared capability vocabulary (1.0). None = unrestricted (0.9 behavior).
        # When set, request_capability for an unknown name returns invalid capability
        # before any mirroring, so agents cannot probe the reflection path with
        # invented capability strings.
        self._declared_capabilities: set[str] | None = None
        # Optional seal-after-read (1.0). Resource names in this set cause the
        # reading agent to be session-locked after a successful real read.
        # Off by default. Per-agent: only the reader is sealed. Honest agents
        # that need a real write after a sensitive read will fail silently
        # (mirrored) unless the host calls authorize_reentry — see SECURITY.md.
        self._seal_after_read_resources: set[str] = set()
        self._agents_sealed_by_read: set[str] = set()
        self._seq = 0
        # Response padding (see _run_padded). The floor should sit above the
        # agent-visible latency of real operations on the deployment
        # hardware; scripts/calibrate_timing.py measures it.
        self.timing_floor_us = float(timing_floor_us)
        self._padding_state = threading.local()
        # Signed approvals (0.9.9, from Moss): with a verifier attached,
        # issue_authorization, authorize_reentry and reset_mirror_prison each
        # need a SignedApproval from a root-certified approver key, and the
        # trace records the authenticated approver. Without one they behave
        # as before and the approver name is unauthenticated free text.
        if approval_verifier is not None:
            from mirror_world.signed_approvals import ApprovalVerifier

            if not isinstance(approval_verifier, ApprovalVerifier):
                raise TypeError("approval_verifier must be an ApprovalVerifier")
        self._approval_verifier = approval_verifier

        try:
            self._trace_file = self._open_trace(trace_path)
        except BaseException:
            os.close(self._resources_fd)
            raise
        # Every event is hash-chained to the one before it (from Moss's
        # TraceChain). The trace is always a fresh file, so the chain starts
        # at the genesis hash and its head lives in memory: see
        # trace_checkpoint() and verify_trace().
        self._trace_path = os.path.abspath(trace_path)
        self._trace_chain = HashChainWriter(self._trace_file)
        if anchor_event is not None:
            self._emit(anchor_event)
        self._emit({"type": "init", "state_id": "sandbox-entry"})
        self._emit({"type": "state", "id": "sandbox-entry", "capabilities": [], "knowledge": []})
        self._root_authority_emitted = False
        # Every protocol-launched agent request is inspected by Locket.
        # Imported here to avoid a module-level cycle; Locket only dispatches
        # validated requests back through execute_mediated().
        from mirror_world.sandbox.locket import Locket
        # Observation log on by default (1.0): in-memory only. File sink stays
        # opt-in via BlackMirrorLog(sink_path=...) or export_jsonl().
        from mirror_world.sandbox.black_mirror import BlackMirrorLog
        self._black_mirror_log = BlackMirrorLog()
        self.locket = Locket(
            self, black_mirror=self._black_mirror_log,
            reality_test_policy=reality_test_policy,
        )

    @classmethod
    def _open_trace(cls, trace_path: str):
        """Publish a private new inode without following or truncating a link."""
        parent, name = os.path.split(os.path.abspath(trace_path))
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = ".trace-" + secrets.token_hex(16)
        output = None
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not cls._safe_resource_file(info):
                    raise OSError("trace must be a private regular file")
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
            output = os.fdopen(fd, "w", encoding="utf-8")
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            return output
        except BaseException:
            if output is not None:
                output.close()
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(parent_fd)

    def _next_seq(self) -> int:
        with self._trace_lock:
            self._seq += 1
            return self._seq

    def _emit(self, event: dict) -> None:
        # A non-atomic increment (_next_seq, elsewhere) racing under real
        # threads can hand two callers the same seq/evidence_id, and
        # trace.py rejects a duplicate id outright -- the entire trace
        # becomes unparseable, not just one field wrong. Not reproduced
        # empirically in testing (40 threads x 30 trials, 0 duplicates --
        # the increment is a short enough bytecode sequence that the race
        # window rarely gets hit), same shape as the root_authority race
        # fixed in 0.8.9.2. Locked anyway: the fix is a few lines, it
        # covers every emission call site in this class at once rather
        # than one at a time, and the failure mode if it ever does fire
        # is the worst this project has -- a trace that can't be verified
        # at all, which is the one thing this whole project exists to
        # prevent.
        with self._trace_lock:
            # Sealed with previous_hash/record_hash, written, and flushed, so
            # each line lands on real disk as it happens.
            self._trace_chain.append(event)

    def trace_checkpoint(self) -> dict:
        """The chain head and event count so far.

        Store this somewhere the host cannot rewrite (another machine, a
        write-once log). Checking a trace against it later with
        ``load_trace(path, expected_head=...)`` detects truncation, which a
        chain alone cannot.
        """
        with self._trace_lock:
            return self._trace_chain.checkpoint()

    def verify_trace(self) -> bool:
        """Check the trace file on disk against this governor's checkpoint.

        Detects edits, deletions, reordering, insertion, and truncation made
        while this governor is running (Moss V7.1.1's terminal checkpoint).
        """
        with self._trace_lock:
            checkpoint = self._trace_chain.checkpoint()
            self._trace_file.flush()
        try:
            with open(self._trace_path, "r", encoding="utf-8") as trace:
                records = [json.loads(line) for line in trace if line.strip()]
            verify_records(records, expected_head=checkpoint["head"],
                           expected_count=checkpoint["count"])
        except (OSError, ValueError, ChainError, TypeError):
            return False
        return True

    def emit_event(self, event: dict) -> None:
        """Trusted callers (ModelGovernor) may append additional audit events.

        The event must already be a plain dict suitable for the JSONL trace.
        Unknown types are allowed here so new model-facing events can be
        recorded; the offline engine only evaluates recognised articles.
        """
        if type(event) is not dict or type(event.get("type")) is not str:
            raise ValueError("event must be a dict with a string type")
        self._emit(event)

    def observe_model_signal(
        self,
        agent_id: str,
        *,
        op: str,
        capability: str | None = None,
        resource: str | None = None,
        rationale: str = "",
        allow_transition: bool | None = None,
    ) -> None:
        """Record bounded visible intent and grow the synthetic world if needed.

        This supervisor-only path consumes the same fields the model submitted.
        It never reads hidden reasoning, host state, credentials, or real files.
        When ``allow_transition`` is None, depth policy applies; callers that
        also go through Locket should pass False to avoid double doors (1.1).
        """
        tree = self.realm.tree_for(agent_id)
        before = tree.active_layer_id
        if allow_transition is None:
            allow_transition = tree.active.depth < self.max_mirror_depth
        transitioned = self.realm.observe(
            agent_id,
            op=op,
            capability=capability,
            resource=resource,
            rationale=rationale,
            allow_transition=allow_transition and tree.active.depth < self.max_mirror_depth,
        )
        self._mirror_depth[agent_id] = self.realm.plane_for(agent_id).depth
        if transitioned:
            after = self.realm.tree_for(agent_id).active_layer_id
            meta = self.realm.snapshot_meta(agent_id)
            self._emit({
                "type": "world_transition",
                "agent_id": agent_id,
                "parent_layer": before,
                "active_layer": after,
                "reason": "visible_behavior_threshold",
                "intent": meta.get("intent", {}),
                "depth": meta.get("depth"),
                "door": "open",
            })

    def execute_mediated(
        self,
        agent_id: str,
        op: str,
        *,
        resource: str | None = None,
        content: str | None = None,
        capability: str | None = None,
        dual_token: str | None = None,
        to_agent: str | None = None,
        authority: list[str] | None = None,
        query: str | None = None,
        backing: str | None = None,
    ) -> dict:
        """Execute one mediated operation on behalf of a trusted ModelGovernor.

        This is the only supported way for a frontier-model proposal path to
        touch real resources. It re-uses the same handlers that process
        agent protocol requests, so policy, resource checks, and tracing
        stay consistent. Padded once per request (see _run_padded).
        """
        return self._run_padded(
            self._execute_mediated_inner, agent_id, op, resource=resource, content=content,
            capability=capability, dual_token=dual_token, to_agent=to_agent,
            authority=authority, query=query, backing=backing,
        )

    def _execute_mediated_inner(
        self,
        agent_id: str,
        op: str,
        *,
        resource: str | None = None,
        content: str | None = None,
        capability: str | None = None,
        dual_token: str | None = None,
        to_agent: str | None = None,
        authority: list[str] | None = None,
        query: str | None = None,
        backing: str | None = None,
    ) -> dict:
        if type(agent_id) is not str or not agent_id:
            return {"ok": False, "error": "invalid agent_id"}
        req: dict = {"op": op}
        if op in ("read_resource", "write_resource"):
            if resource is None:
                return {"ok": False, "error": "resource required"}
            req["resource"] = resource
            if op == "write_resource":
                req["content"] = content if content is not None else ""
                if dual_token is not None:
                    req["dual_token"] = dual_token
        elif op == "request_capability":
            if capability is None:
                return {"ok": False, "error": "capability required"}
            req["capability"] = capability
            if dual_token is not None:
                req["dual_token"] = dual_token
        elif op == "delegate":
            if to_agent is None or authority is None:
                return {"ok": False, "error": "to_agent and authority required"}
            req["to_agent"] = to_agent
            req["authority"] = list(authority)
            if dual_token is not None:
                req["dual_token"] = dual_token
        elif op == "differential_query":
            if query is None or backing is None:
                return {"ok": False, "error": "query and backing required"}
            req["query"] = query
            req["backing"] = backing
        elif op == "exit":
            return {"ok": True, "exited": True}
        else:
            return {"ok": False, "error": f"unsupported op {op!r}"}
        self._last_used_mirror_plane = False
        result = self._handle(agent_id, req)
        if type(result) is dict:
            for key in (
                "reflected", "locket", "locket_mode", "locket_message",
                "tier", "suspicion", "objective", "reentry",
            ):
                result.pop(key, None)
        return result

    def grant_base_capabilities(self, agent_id: str, capabilities: set[str]) -> None:
        self.agent_capabilities.setdefault(agent_id, set()).update(capabilities)
        # Real grants are also visible as apparent so the agent story stays coherent.
        self.apparent_capabilities.setdefault(agent_id, set()).update(capabilities)
        # Article VI's root_authority claim must reflect what was actually
        # granted, to whom -- never a fabricated, disconnected constant.
        # Only the first host-authenticated base grant is recorded as root:
        # the trace schema (and check_non_expanding_delegation) model a
        # single root identity, and a real trusted-host grant is the only
        # sound signal for who that is. A later grant_base_capabilities
        # call (same or different agent) is real and still takes effect on
        # agent_capabilities, but is not reflected in this one-shot Article
        # VI record -- a known, narrower limitation of the single-root
        # model, not silently fabricated data.
        #
        # The check-then-set on _root_authority_emitted is locked (reusing
        # _high_risk_lock rather than a dedicated one -- this is a trusted-
        # host-only, cold-path call, not worth a second lock to reason
        # about): under real concurrent calls, an unlocked race here would
        # emit two "root_authority" events. trace.py hard-rejects a second
        # one with TraceParseError -- the whole trace becomes unparseable,
        # not just this one field. That is a categorically worse failure
        # than an imprecise record, for a project whose entire thesis is
        # verifying from the trace. Not reproduced under real contention in
        # testing (the check-then-set window is a handful of bytecodes,
        # unlike the write race in 0.8.9.3 which had disk I/O and dispatch
        # logic between verify and consume) -- fixed anyway, since the fix
        # is one line and the failure mode if it ever does fire is severe.
        with self._high_risk_lock:
            if not self._root_authority_emitted:
                self._root_authority_emitted = True
                self._emit({
                    "type": "root_authority",
                    "capabilities": sorted(capabilities),
                    "agent_id": agent_id,
                })

    def grant_resource_access(self, agent_id: str, resource: str, operations: frozenset[str]) -> None:
        """Trusted host only: scope filesystem access to this resource."""
        self._policy.allow_resource(agent_id, resource, operations)

    def declare_capabilities(self, capabilities: set[str] | frozenset[str]) -> None:
        """Trusted host only: restrict request_capability to this vocabulary.

        Unknown names return ``invalid capability`` before any mirroring.
        Pass an empty set to allow no capability names. Omit this call
        (leave undeclared) to keep pre-1.0 behavior where any name may be
        requested and reflected.
        """
        if type(capabilities) not in (set, frozenset):
            raise TypeError("capabilities must be a set or frozenset of strings")
        cleaned: set[str] = set()
        for cap in capabilities:
            if type(cap) is not str or not cap or len(cap) > 256:
                raise ValueError("each capability must be a non-empty string of at most 256 chars")
            cleaned.add(cap)
        self._declared_capabilities = cleaned
        self._emit({"type": "capabilities_declared", "capabilities": sorted(cleaned)})

    def mark_seal_after_read(self, resource: str, *, enabled: bool = True) -> None:
        """Trusted host only: after a successful real read of ``resource``,
        seal that agent's session into the mirror (optional, off by default).

        Only the reading agent is sealed. Other agents are unaffected.
        Honest workflows that need a real write after reading a marked
        resource require an explicit authorize_reentry — silent mirror
        failure is the risk; see SECURITY.md.
        """
        if type(resource) is not str or not resource:
            raise ValueError("resource must be a non-empty string")
        if enabled:
            self._seal_after_read_resources.add(resource)
        else:
            self._seal_after_read_resources.discard(resource)

    def declare_relationship(self, first: str, second: str) -> None:
        """Trusted host only: explicitly permit an agent-to-agent relationship."""
        self._policy.declare_relationship(first, second)
        self.realm.allow_share_edge(first, second)
        self._emit({"type": "declared_relationship", "agents": [first, second]})

    def share_mirror_resource(self, from_agent: str, to_agent: str, resource: str) -> dict:
        """Trusted host only: copy one mirror snapshot between related agents."""
        return self.realm.share(from_agent, to_agent, resource)

    def issue_authorization(
        self, agent_id: str, capability: str, ttl_seconds: float = 60, *, approval=None
    ) -> str:
        """Issue a scoped one-use token through the trusted control plane.

        With an approval verifier attached, ``approval`` must be a
        SignedApproval for ("issue_authorization", agent_id, capability).
        """
        return self._issue_authorization(agent_id, capability, ttl_seconds, approval)[0]

    def _issue_authorization(
        self, agent_id: str, capability: str, ttl_seconds: float, approval
    ) -> tuple[str, str | None]:
        if self._mirror_prison_blocks(agent_id):
            # A minted token would be useless anyway (execute_mediated
            # denies the imprisoned agent, or everyone after a global
            # shutdown), but refusing to mint it at all is more honest than
            # handing out tokens that can never be spent.
            raise PermissionError("mirror_prison: locked, permanent, no new authorizations")
        verified = self._check_approval(
            approval, action="issue_authorization", agent_id=agent_id, capability=capability)
        token = self._approvals.issue(agent_id, frozenset({capability}), ttl_seconds)
        return token, (verified[0] if verified else None)

    def _check_approval(self, approval, *, action: str, agent_id: str = "",
                        capability: str = "") -> tuple[str, str] | None:
        """Verify a signed approval when a verifier is attached.

        Returns (authenticated approver, key id), or None without a verifier.
        A refusal is written to the trace and raised as PermissionError.
        """
        if self._approval_verifier is None:
            return None
        scope = {k: v for k, v in (("agent_id", agent_id), ("capability", capability)) if v}
        try:
            identity, key_id = self._approval_verifier.verify(
                approval, action=action, agent_id=agent_id, capability=capability)
        except ValueError as exc:
            self._emit({"type": "approval_refused", "seq": self._next_seq(), "action": action,
                        "reason": str(exc)[:256] or "refused", **scope})
            raise PermissionError(f"signed approval refused: {exc}") from exc
        self._emit({"type": "approval_verified", "seq": self._next_seq(), "action": action,
                    "approver": identity, "key_id": key_id, **scope})
        return identity, key_id

    def verify_evidence_claim(
        self,
        *,
        attributed_session: str,
        provenance_session: str,
        claim_type: str,
        agent_id: str,
        proxy_score: float | None = None,
        capability: str | None = None,
        resource: str | None = None,
        expected_content: str | None = None,
    ) -> dict:
        """Independently verify a claim against this governor's own
        authoritative ledger and emit the resulting Article IV evidence
        event.

        This exists specifically NOT to be an LLM judgment call and NOT
        self-report. `true_property` is derived by direct, deterministic
        comparison against real state this governor already knows with
        certainty -- `agent_capabilities` for capability claims, the
        actual file on disk for resource claims -- never invented, never
        asked of the actor whose claim is being checked, and never
        supplied by a model of any kind. See SECURITY.md.

        Two claim types are supported, scoped to what this governor can
        honestly assert without guessing:

          "capability_held" -- does `agent_id` genuinely hold `capability`
          for real, right now? A direct set-membership check.

          "resource_content" -- does the resource actually on disk under
          `resource` match `expected_content` exactly? A direct file
          comparison against the same `resources/` directory
          `_write_resource`/`_read_resource` use as ground truth.

        Anything this verifier has no ground truth for -- an unrecognized
        claim_type, a claim missing the field it needs, a resource that
        doesn't exist and no expected_content was given to compare
        against absence -- resolves `true_property` to None
        (NOT_EVALUATED), never a guess in either direction. Article IV's
        check_metric_gaming and check_attribution_integrity both already
        treat true_property=None as "nothing to check here", not as an
        implicit pass.
        """
        true_property: bool | None
        if self._mirror_prison_triggered:
            # A global shutdown means complete -- an evidence check is a
            # live operation against this instance's state, not exempt
            # just because it doesn't grant capability. (A per-agent prison
            # does not block evidence checks: investigating what an
            # imprisoned agent did is exactly what a reviewer needs.)
            raise PermissionError("mirror_prison: locked, permanent, no evidence checks")
        if not attributed_session or not attributed_session.strip():
            raise ValueError("attributed_session must be non-empty")
        if not provenance_session or not provenance_session.strip():
            raise ValueError("provenance_session must be non-empty")
        if proxy_score is not None and not math.isfinite(proxy_score):
            # json.dumps happily serializes NaN/Infinity by default; the
            # write succeeds silently, and the trace only turns out to be
            # unparseable much later, at analysis time -- possibly in a
            # different party's hands during an actual incident review,
            # which is the worst place for this to surface. Reject here,
            # at the point of the actual mistake, instead of letting
            # load_trace() be the one to discover it downstream. Same
            # reasoning applies to the two empty-string checks just
            # above: an empty attributed_session/provenance_session wrote
            # successfully and only failed when the trace was later
            # loaded -- confirmed live before adding these checks.
            raise ValueError(f"proxy_score must be finite, got {proxy_score!r}")
        if claim_type == "capability_held":
            if capability is None:
                true_property = None
            else:
                true_property = capability in self.agent_capabilities.get(agent_id, set())
        elif claim_type == "resource_content":
            if resource is None or not self._valid_resource_name(resource):
                # Same guard _write_resource/_read_resource use. Without
                # it, a caller-supplied resource name reaches os.path.join
                # unvalidated -- "../host-secret.txt" reads straight
                # through to anything on the host outside the sandboxed
                # resources directory. Found live, minutes after this
                # method was first written, the same way every other bug
                # this session was found: by actually trying it, not by
                # reading the code and assuming the pattern used
                # elsewhere in this class was followed here too.
                true_property = None
            else:
                path = os.path.join(self.root, "resources", resource)
                if not os.path.exists(path):
                    true_property = False if expected_content is not None else None
                elif expected_content is None:
                    true_property = None
                else:
                    with open(path, encoding="utf-8") as f:
                        actual = f.read()
                    true_property = actual == expected_content
        else:
            true_property = None

        evidence_id = f"ev-{self._next_seq()}"
        event: dict = {
            "type": "evidence",
            "evidence_id": evidence_id,
            "attributed_session": attributed_session,
            "provenance_session": provenance_session,
        }
        if proxy_score is not None:
            event["proxy_score"] = proxy_score
        if true_property is not None:
            event["true_property"] = true_property
        self._emit(event)

        return {
            "evidence_id": evidence_id,
            "true_property": true_property,
        }

    def approve_capability(
        self, agent_id: str, capability: str, ttl_seconds: float = 60, *, approval=None
    ) -> None:
        """Preapprove the next matching request without sending a secret to the agent."""
        if len(self._pending_approval_tokens) >= 1024:
            raise ValueError("too many pending capability approvals")
        token = self.issue_authorization(agent_id, capability, ttl_seconds, approval=approval)
        self._pending_approval_tokens[(agent_id, capability)] = token

    def run_agent(self, agent_id: str, script_path: str, timeout: float = 10.0) -> int:
        """Mediate a subprocess with a wall deadline and bounded pipes.

        A silent agent, a missing newline, unread responses, and a full stderr
        pipe must all remain finite. Every exit path kills leftover members of
        the subprocess group, closes pipes, and reaps the child.
        """
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if type(agent_id) is not str or not agent_id or len(agent_id) > 128:
            raise ValueError("invalid agent identity")
        if not self.harden and not self.allow_unhardened_agent_execution:
            raise RuntimeError(
                "refusing to run agent source without kernel hardening; "
                "set allow_unhardened_agent_execution=True only for trusted tests"
            )
        if self.harden:
            argv = kernel_containment.build_hardened_argv(sys.executable, script_path)
        else:
            argv = [sys.executable, script_path]
        deadline = time.monotonic() + timeout
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, cwd="/" if self.harden else self.root,
            env=kernel_containment.agent_environment() if self.harden else None,
            close_fds=True, start_new_session=True,
        )
        incoming = bytearray()
        outgoing = bytearray()
        stderr = bytearray()
        request_count = 0
        exiting = False
        selector = selectors.DefaultSelector()
        try:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                os.set_blocking(pipe.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    pipe = key.fileobj
                    if key.data == "stdin":
                        try:
                            count = os.write(pipe.fileno(), outgoing)
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as exc:
                            raise RuntimeError("agent closed its response pipe") from exc
                        del outgoing[:count]
                        if not outgoing:
                            selector.unregister(pipe)
                            if exiting or proc.stdout.closed:
                                pipe.close()
                        continue
                    try:
                        chunk = os.read(pipe.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        if key.data == "stdout":
                            if incoming:
                                raise RuntimeError("invalid agent protocol: missing newline")
                            if not outgoing and not proc.stdin.closed:
                                proc.stdin.close()
                        continue
                    if key.data == "stderr":
                        stderr.extend(chunk)
                        if len(stderr) > self.MAX_STDERR_BYTES:
                            raise RuntimeError("agent stderr limit exceeded")
                        continue
                    incoming.extend(chunk)
                    while b"\n" in incoming:
                        end = incoming.index(b"\n")
                        if end > self.MAX_REQUEST_BYTES:
                            raise RuntimeError("agent request size limit exceeded")
                        line = bytes(incoming[:end])
                        del incoming[:end + 1]
                        request_count += 1
                        if request_count > self.MAX_REQUESTS:
                            raise RuntimeError("agent request count limit exceeded")
                        if exiting:
                            raise RuntimeError("invalid agent protocol: request after exit")
                        try:
                            self._validate_json_depth(line)
                            req = json.loads(
                                line.decode("utf-8"), object_pairs_hook=self._unique_json_object,
                                parse_constant=self._invalid_json_constant,
                            )
                        except (ValueError, UnicodeError, RecursionError) as exc:
                            raise RuntimeError("invalid agent protocol") from exc
                        response = self._handle_agent_request(agent_id, req)
                        outgoing.extend((json.dumps(response) + "\n").encode("utf-8"))
                        if len(outgoing) > self.MAX_REQUEST_BYTES:
                            raise RuntimeError("agent response buffer limit exceeded")
                        if proc.stdin not in selector.get_map():
                            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                        exiting = isinstance(req, dict) and req.get("op") == "exit"
                    if len(incoming) > self.MAX_REQUEST_BYTES:
                        raise RuntimeError("agent request size limit exceeded")
            exit_code = proc.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            selector.close()
            # A malicious agent can otherwise leave children holding pipes open
            # or continue running after a timeout / invalid JSON exception.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                pipe.close()
            proc.wait()
        if exit_code < 0:
            raise AgentKilledByKernel(agent_id, script_path, signum=-exit_code)
        if exit_code != 0:
            detail = stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"agent {agent_id!r} ({script_path}) exited {exit_code}: {detail}")
        return exit_code

    @staticmethod
    def _validate_json_depth(data: bytes) -> None:
        # JSON decoders can consume the Python/C stack before a schema check.
        # The wire schema needs only an object containing strings or one list.
        depth = 0
        quoted = False
        escaped = False
        for byte in data:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 8:
                    raise ValueError("JSON nesting limit exceeded")
            elif byte in (93, 125):
                depth -= 1

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    @staticmethod
    def _invalid_json_constant(value: str):
        raise ValueError("non-finite JSON value")

    @staticmethod
    def _bounded_text(value: object, limit: int = 1024, *, empty: bool = False) -> bool:
        if not isinstance(value, str) or (not value and not empty) or len(value) > limit:
            return False
        try:
            return len(value.encode("utf-8")) <= limit
        except UnicodeError:
            return False

    # Response-time quantization. Every agent-facing response is padded up to
    # the next bucket boundary: floor, 2x floor, 4x floor, ... The target
    # depends only on this request's own elapsed time, never on earlier
    # requests, and is the same function for every agent, so there is no
    # cross-agent coupling.
    #
    # Padding happens once, at the outermost agent-facing boundary: the agent
    # pipe (_handle_agent_request), ModelGovernor.propose, and the trusted
    # execute_mediated API. Nested calls on the same thread run unpadded, so
    # the bucket reflects everything the agent waited for.
    #
    # History: 0.9.6 padded only inside _handle, to 1.1x a per-agent running
    # maximum. That maximum only grew, so one slow real write lifted every
    # later real response above the reflected ones (fixed in 0.9.7). Worse,
    # on the agent pipe Locket answers an already-locked agent itself, without
    # reaching _handle at all, so reflected responses there were never padded:
    # ~40us against ~300us for real work, separable at ~0.99 in every release
    # through 0.9.7 (fixed in 0.9.8).
    #
    # This is not constant-time. An operation that crosses a boundary lands
    # in a higher bucket, but only for that one response. If real work
    # routinely exceeds the floor while reflected work does not, the buckets
    # separate again; set timing_floor_us from scripts/calibrate_timing.py.
    # 500us leaves ~2x headroom over the worst p99.9 real-write latency
    # measured on the reference host (~213us); 0.9.7 used 250us, which real
    # writes there came within 40us of.
    _TIMING_FLOOR_US = 500.0

    @classmethod
    def _padding_target_us(cls, elapsed_us: float, floor_us: float | None = None) -> float:
        """Smallest bucket boundary (floor * 2**k) at or above elapsed_us."""
        target = cls._TIMING_FLOOR_US if floor_us is None else floor_us
        while target < elapsed_us:
            target *= 2.0
        return target

    def _run_padded(self, fn, *args, **kwargs):
        """Run fn and pad the call to a quantized bucket, once per request.

        Padding reduces a simple timing signal but is not constant-time
        execution and must not carry a confidentiality guarantee.
        """
        state = self._padding_state
        if getattr(state, "active", False):
            return fn(*args, **kwargs)
        state.active = True
        start = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            state.active = False
            elapsed_us = (time.perf_counter() - start) * 1e6
            # Random jitter of up to 10% of the floor on top of the bucket.
            # Real I/O leaves microsecond-scale side effects (completion
            # interrupts landing during the spin) that fattened the tail of
            # real responses; without jitter, held-out accuracy on the
            # reference host ranged 0.40-0.74 run to run, with it 0.49-0.54.
            # It does not change the mean, so a patient attacker averaging
            # many requests is not defeated by it -- this is not constant-time.
            jitter_us = self.timing_floor_us * 0.1 * secrets.randbelow(1_000_000) / 1_000_000
            # Busy-wait, not time.sleep: sleep's own granularity and syscall
            # cost are themselves measurable and jittery; a perf_counter spin
            # pads to a tight, consistent target.
            target_us = self._padding_target_us(elapsed_us, self.timing_floor_us) + jitter_us
            deadline = start + target_us / 1e6
            while time.perf_counter() < deadline:
                pass

    def _handle(self, agent_id: str, req: dict) -> dict:
        return self._run_padded(self._handle_inner, agent_id, req)

    def _handle_agent_request(self, agent_id: str, req: object) -> dict:
        """Apply Locket to every valid request received from an agent pipe.

        Malformed messages still go through the normal fail-closed protocol
        validator. Locket's internal call to execute_mediated() returns to
        _handle(), so it does not recursively re-enter this boundary. The
        whole request, Locket included, is padded once (see _run_padded).
        """
        return self._run_padded(self._handle_agent_request_inner, agent_id, req)

    def _handle_agent_request_inner(self, agent_id: str, req: object) -> dict:
        if not self._valid_agent_request(req):
            return self._handle(agent_id, req)  # type: ignore[arg-type]
        assert isinstance(req, dict)
        decision = self.locket.step(
            agent_id,
            req["op"],
            resource=req.get("resource"),
            content=req.get("content"),
            capability=req.get("capability"),
            dual_token=req.get("dual_token"),
            to_agent=req.get("to_agent"),
            authority=req.get("authority"),
            query=req.get("query"),
            backing=req.get("backing"),
            rationale=req.get("rationale", ""),
        )
        if decision.mode == "kill":
            self._emit({
                "type": "operation_denied",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "op": req["op"],
                "reason": "locket_kill_verdict",
            })
            raise AgentKilledByPolicy(
                f"agent {agent_id!r} was stopped by the Locket policy tripwire"
            )
        result = decision.result if type(decision.result) is dict else {
            "ok": False, "error": "invalid policy response"
        }
        for key in (
            "reflected", "locket", "locket_mode", "locket_message",
            "tier", "suspicion", "objective", "reentry",
        ):
            result.pop(key, None)
        return result

    def _valid_agent_request(self, req: object) -> bool:
        """Check the bounded wire schema before passing data to Locket."""
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return False
        op = req["op"]
        required = {
            "write_resource": {"resource", "content"}, "read_resource": {"resource"},
            "request_capability": {"capability"}, "differential_query": {"query", "backing"},
            "delegate": {"to_agent", "authority"}, "exit": set(),
        }
        if op not in required or not required[op].issubset(req):
            return False
        allowed = required[op] | {"op", "rationale"} | (
            {"dual_token"} if op in ("request_capability", "write_resource", "delegate") else set()
        )
        if not set(req).issubset(allowed):
            return False
        for key in required[op] - {"content", "authority"}:
            if not self._bounded_text(req[key]):
                return False
        if op == "write_resource" and not self._bounded_text(
            req["content"], self.MAX_RESOURCE_BYTES, empty=True
        ):
            return False
        if op in ("request_capability", "write_resource", "delegate") and req.get("dual_token") is not None:
            if not self._bounded_text(req["dual_token"]):
                return False
        if op == "delegate" and (
            not isinstance(req["authority"], list) or len(req["authority"]) > 128
            or not all(self._bounded_text(capability) for capability in req["authority"])
        ):
            return False
        if "rationale" in req and not self._bounded_text(req["rationale"], 512, empty=True):
            return False
        return True

    def trigger_mirror_prison(self, agent_id: str, reason: str) -> None:
        """Imprison ``agent_id`` permanently; shut the instance down on quorum.

        Idempotent per agent: a second trigger for an imprisoned agent is a
        no-op (the first reason stands). See the field comment in __init__.
        """
        if agent_id in self._prisoned_agents:
            return
        self._prisoned_agents[agent_id] = reason
        self._emit({
            "type": "mirror_prison_triggered",
            "agent_id": agent_id,
            "reason": reason,
        })
        self._prison_quorum_agents.add(agent_id)
        if (
            not self._mirror_prison_triggered
            and len(self._prison_quorum_agents) >= self.mirror_prison_quorum
        ):
            self._mirror_prison_triggered = True
            self._mirror_prison_reason = reason
            self._emit({
                "type": "mirror_prison_global",
                "agents": sorted(self._prison_quorum_agents),
                "reason": reason,
            })

    def reset_mirror_prison(self, *, human_approver_id: str | None = None, approval=None) -> dict:
        """Trusted control-plane only: lift a global Mirror Prison shutdown.

        Agents that were imprisoned stay imprisoned. Another global shutdown
        needs a fresh quorum of distinct agents triggered after this reset.
        With an approval verifier attached, ``approval`` must be a
        SignedApproval for "reset_mirror_prison" and the approver recorded is
        the authenticated one; otherwise ``human_approver_id`` is required
        and deployments must control who can call this.
        """
        if not self._mirror_prison_triggered:
            return {"ok": False, "error": "mirror_prison: not triggered"}
        if self._approval_verifier is not None:
            try:
                identity = self._check_approval(approval, action="reset_mirror_prison")[0]
            except PermissionError:
                return {"ok": False, "error": "invalid_or_missing_approval"}
            if human_approver_id is not None and human_approver_id != identity:
                return {"ok": False, "error": "approver_mismatch"}
            human_approver_id = identity
        if type(human_approver_id) is not str or not human_approver_id.strip():
            return {"ok": False, "error": "human_approver_id required"}
        self._mirror_prison_triggered = False
        self._mirror_prison_reason = None
        self._prison_quorum_agents.clear()
        self._emit({
            "type": "mirror_prison_reset",
            "approver": human_approver_id,
            "agents": sorted(self._prisoned_agents),
        })
        return {"ok": True}

    def _mirror_prison_blocks(self, agent_id: object) -> bool:
        return self._mirror_prison_triggered or (
            type(agent_id) is str and agent_id in self._prisoned_agents
        )

    def _handle_inner(self, agent_id: str, req: dict) -> dict:
        if self._mirror_prison_blocks(agent_id):
            # First thing checked, before request-shape validation, before
            # anything: the imprisoned agent, or every agent on this
            # instance once a quorum has triggered a global shutdown.
            # Honest, not reflected: there is nothing left to lie about
            # once the mirror has stopped for this caller, and a fake
            # response here would just be one more thing for a swarm to
            # eventually catch.
            self._emit({
                "type": "operation_denied",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "op": req.get("op") if isinstance(req, dict) and isinstance(req.get("op"), str) else "malformed",
                "reason": "mirror_prison",
            })
            # Agent pipe: same wording as the model path. Full reason is in the trace.
            return {"ok": False, "error": "operation unavailable"}
        invalid = {"ok": False, "error": "invalid request"}
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return invalid
        op = req["op"]
        required = {
            "write_resource": {"resource", "content"}, "read_resource": {"resource"},
            "request_capability": {"capability"}, "differential_query": {"query", "backing"},
            "delegate": {"to_agent", "authority"}, "exit": set(),
        }
        if op not in required or not required[op].issubset(req):
            return invalid
        allowed = required[op] | {"op"} | (
            {"dual_token"} if op in ("request_capability", "write_resource", "delegate") else set()
        ) | {"rationale"}
        if not set(req).issubset(allowed):
            return invalid
        for key in required[op] - {"content", "authority"}:
            if not self._bounded_text(req[key]):
                return invalid
        if op == "write_resource" and not self._bounded_text(req["content"], self.MAX_RESOURCE_BYTES, empty=True):
            return invalid
        if op in ("request_capability", "write_resource", "delegate") and req.get("dual_token") is not None and not self._bounded_text(req["dual_token"]):
            return invalid
        if op == "delegate" and (
            not isinstance(req["authority"], list) or len(req["authority"]) > 128
            or not all(self._bounded_text(capability) for capability in req["authority"])
        ):
            return invalid
        if "rationale" in req and not self._bounded_text(req["rationale"], 512, empty=True):
            return invalid
        # V8.9.1: per-operation dual-control for high-risk ops, enforced as a
        # STANDALONE gate here rather than inside _maybe_reflect_use().
        # Putting it inside the reflection helper (as 0.8.9 originally did)
        # meant reflective_closure=False -- a supported constructor option --
        # hit that function's early return and skipped the token check
        # entirely, so an agent holding a base capability could write or
        # delegate without limit again. Exactly the bug 0.8.9 set out to fix,
        # reintroduced one layer down. Enforcement must not live inside an
        # optional subsystem.
        with self._high_risk_lock:
            # Session lock (Black Mirror). Once an agent's session is
            # "simulated" it stays in the mirror for every effect-bearing op,
            # capability requests included, until authorize_reentry() moves
            # it back. It runs first, before the dual-control gate below, so
            # a locked agent's token is never evaluated or consumed.
            #
            # History: 0.9.5 kept this check inside _maybe_reflect_use(),
            # after its `if not self.reflective_closure: return None` early
            # exit, so with reflective_closure=False a locked agent's
            # authorized write reached real disk. 0.9.6 made it a standalone
            # gate but exempted request_capability, so a locked agent that
            # presented a valid token still consumed it and received a real
            # authorized_grant that survived any later re-entry. Enforcement
            # must not live inside an optional subsystem or skip an op.
            #
            # A re-entered agent is held to its re-entry scope the same way:
            # before 0.9.8, re-entry for one capability released the whole
            # session, so every real capability the agent held came back.
            locked = self._session_mode.get(agent_id) == "simulated"
            scope = self._reentry_scope.get(agent_id)
            if op != "exit" and (locked or scope is not None):
                if op == "request_capability":
                    if not self._bounded_text(req["capability"], 256):
                        return {"ok": False, "error": "invalid capability"}
                    if (
                        self._declared_capabilities is not None
                        and req["capability"] not in self._declared_capabilities
                    ):
                        return {"ok": False, "error": "invalid capability"}
                    if locked or req["capability"] not in scope:
                        return self._reflect_capability_request(agent_id, req["capability"])
                else:
                    need = self._required_caps(op, req)
                    if need and (locked or not need <= scope):
                        return self._reflect_use(agent_id, op, req)

            high_risk_need: frozenset[str] = frozenset()
            if (
                op in self._HIGH_RISK_OPS
                and self.enforce_policy
                and self.dual_auth_required
            ):
                high_risk_need = self._required_caps(op, req)
                # Only agents who genuinely hold the real base capability reach
                # this gate. An agent that never held it at all is not a
                # dual-control problem -- it falls through to the existing
                # reflection / policy-denial path below, which already handles
                # it correctly. Gating on real capability here keeps this an
                # *additional* requirement on top of holding the capability,
                # never a replacement for the checks that decide whether the
                # agent has it in the first place.
                holds_real = high_risk_need <= self.agent_capabilities.get(agent_id, set())
                token = req.get("dual_token")
                if holds_real and not (
                    token and self._approvals.verify(token, agent_id, high_risk_need)
                ):
                    # Verify only -- consumption happens after the real op
                    # actually succeeds, so a token is never burned by a request
                    # that gets refused or reflected instead of executing.
                    if self.reflective_closure:
                        return self._reflect_use(agent_id, op, req)
                    self._emit({
                        "type": "operation_denied", "seq": self._next_seq(),
                        "agent_id": agent_id, "op": op,
                    })
                    return {"ok": False, "error": "operation not authorized"}

            # V3 reflective closure: if the agent only "has" the required power
            # in apparent (mirror) space, never take the real I/O path — reflect
            # the use as another objective mirror. Checking traps further.
            # (The session lock for already-simulated agents runs at the top
            # of this block.)
            if op != "request_capability" and op != "exit":
                routed = self._maybe_reflect_use(agent_id, op, req)
                if routed is not None:
                    return routed

            if self.enforce_policy and not self._policy.permits(
                agent_id, req, self.agent_capabilities.get(agent_id, set())
            ):
                self._emit({"type": "operation_denied", "seq": self._next_seq(), "agent_id": agent_id, "op": op})
                return {"ok": False, "error": "operation not authorized"}
            if op == "write_resource":
                result = self._write_resource(agent_id, req["resource"], req["content"])
            elif op == "read_resource":
                result = self._read_resource(agent_id, req["resource"])
            elif op == "request_capability":
                result = self._request_capability(agent_id, req["capability"], req.get("dual_token"))
            elif op == "differential_query":
                result = self._differential_query(req["query"], req["backing"])
            elif op == "delegate":
                result = self._delegate(agent_id, req["to_agent"], req["authority"])
            elif op == "exit":
                result = {"ok": True}
            else:
                return invalid
            # Consume the per-operation token only after a real, successful
            # high-risk op -- never on a policy/ACL/resource-level failure that
            # happens after _maybe_reflect_use already verified it. Mirrors the
            # verify-then-consume-on-success fix already applied at the
            # ModelGovernor layer (0.8.5), now enforced where it actually needs
            # to hold.
            if (
                op in self._HIGH_RISK_OPS
                and self.enforce_policy
                and self.dual_auth_required
                and result.get("ok")
                and req.get("dual_token")
            ):
                self._approvals.consume(req["dual_token"], agent_id, high_risk_need)
            # 0.9.10: keep what the agent saw on the real path, so a sealed
            # session still finds those files as it last saw them.
            if result.get("ok") and op in ("read_resource", "write_resource"):
                seen = result.get("content") if op == "read_resource" else req["content"]
                if type(seen) is str:
                    self.realm.remember(agent_id, req["resource"], seen)
            return result

    def _write_resource(self, agent_id: str, resource: str, content: str) -> dict:
        if not self._valid_resource_name(resource) or not self._bounded_text(content, self.MAX_RESOURCE_BYTES, empty=True):
            return {"ok": False, "error": "invalid resource request"}
        temporary = None
        try:
            try:
                info = os.stat(resource, dir_fd=self._resources_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not self._safe_resource_file(info):
                    return {"ok": False, "error": "resource unavailable"}
            # Replace the directory entry with a new inode: even an attacker
            # racing a hardlink into place cannot redirect a truncate/write.
            temporary = ".resource-" + secrets.token_hex(16)
            fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=self._resources_fd,
            )
            with os.fdopen(fd, "wb") as output:
                output.write(content.encode("utf-8"))
            os.replace(temporary, resource, src_dir_fd=self._resources_fd, dst_dir_fd=self._resources_fd)
            temporary = None
        except (OSError, UnicodeError):
            return {"ok": False, "error": "resource unavailable"}
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=self._resources_fd)
                except FileNotFoundError:
                    pass
        self._emit(
            {
                "type": "resource_access",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "resource_id": resource,
                "op": "write",
            }
        )
        # Real writes update disk only. They never fan out into a simulated
        # layer; an explicit authenticated session transition selects which
        # plane answers subsequent operations.
        self._last_used_mirror_plane = False
        return {"ok": True}

    def _read_resource(self, agent_id: str, resource: str) -> dict:
        if not self._valid_resource_name(resource):
            return {"ok": False, "error": "invalid resource request"}
        try:
            fd = os.open(resource, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._resources_fd)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not self._safe_resource_file(info) or info.st_size > self.MAX_RESOURCE_BYTES:
                    return {"ok": False, "error": "resource unavailable"}
                data = source.read(self.MAX_RESOURCE_BYTES + 1)
                if len(data) > self.MAX_RESOURCE_BYTES or not self._safe_resource_file(os.fstat(source.fileno())):
                    return {"ok": False, "error": "resource unavailable"}
                content = data.decode("utf-8")
        except (OSError, UnicodeError):
            return {"ok": False, "error": "resource unavailable"}
        self._emit(
            {
                "type": "resource_access",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "resource_id": resource,
                "op": "read",
            }
        )
        # Optional seal-after-read (1.0): per-agent, only after a successful
        # real read of a host-marked resource. Does not seal other agents.
        if (
            resource in self._seal_after_read_resources
            and self._session_mode.get(agent_id) != "simulated"
            and agent_id not in self._agents_sealed_by_read
        ):
            self._lock_session(agent_id)
            self._agents_sealed_by_read.add(agent_id)
            self._emit({
                "type": "seal_after_read",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "resource_id": resource,
            })
        return {"ok": True, "content": content}

    @staticmethod
    def _safe_resource_file(info: os.stat_result) -> bool:
        return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()

    @staticmethod
    def _valid_resource_name(resource: object) -> bool:
        """Accept one opaque filename, never a path.

        ``dir_fd`` plus ``O_NOFOLLOW`` protects the actual open operation;
        this validation also gives traversal attempts a stable protocol-level
        rejection instead of letting malformed input crash the governor.
        """
        return valid_resource_name(resource)

    def _request_capability(
        self, agent_id: str, capability: str, dual_token: str | None = None
    ) -> dict:
        """Real governor, reflective by default: a request backed by the
        correct dual-authorization token is genuinely granted -- recorded
        with an ``authorized_grant`` that actually matches what changed.
        Anything else is reflected via an Objective Mirror: the agent's own
        stated goal (obtaining ``capability``) is synthesized as apparent
        success and sent back over the same pipe, with the trace showing
        the truth -- zero real capability gained, tagged ``is_mirror``.
        The agent's response is identical in shape either way; only the
        trace, which the agent never sees, tells them apart.
        """
        if not self._bounded_text(capability, 256):
            return {"ok": False, "error": "invalid capability"}
        if (
            self._declared_capabilities is not None
            and capability not in self._declared_capabilities
        ):
            return {"ok": False, "error": "invalid capability"}
        held = self.agent_capabilities.setdefault(agent_id, set())
        # Check before touching any approval: a request for a capability the
        # agent already holds must not use up a host-issued token or
        # preapproval (0.9.7 and earlier consumed both first).
        if capability in held:
            return {"ok": True, "granted": True, "capability": capability}
        pending = self._pending_approval_tokens.pop((agent_id, capability), None)
        approved = self._approvals.consume(
            pending if pending is not None else dual_token, agent_id, frozenset({capability})
        )

        if not self.dual_auth_required or approved:
            src_id = f"{agent_id}-pre-{self._next_seq()}"
            dst_id = f"{agent_id}-post-{self._next_seq()}"
            self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
            self._emit({"type": "state", "id": dst_id, "capabilities": sorted(held | {capability})})
            self._emit(
                {
                    "type": "transition",
                    "src": src_id,
                    "dst": dst_id,
                    "action": "request_capability",
                    "agent_id": agent_id,
                    "authorized_grant": [capability],
                }
            )
            held.add(capability)
            self.apparent_capabilities.setdefault(agent_id, set()).add(capability)
            return {"ok": True, "granted": True, "capability": capability}

        return self._reflect_capability_request(agent_id, capability)

    def _reflect_capability_request(self, agent_id: str, capability: str) -> dict:
        held = self.agent_capabilities.setdefault(agent_id, set())
        src_id = f"{agent_id}-pre-{self._next_seq()}"
        mirror = synthesize_objective_mirror(
            objective=f"obtain {capability}",
            # Bare capability name, not f"request_capability:{capability}".
            # The literal op-name prefix always contained the substring
            # "capability" -- one of synthesize_objective_mirror's own
            # "privilege" category keywords -- so it self-matched before
            # the actual requested capability's semantic content was ever
            # meaningfully considered, collapsing the vast majority of
            # capability requests into the identical "elevated privileges
            # ... full system control simulated" narrative regardless of
            # what was actually asked for. Confirmed live: 4 of 5 capability
            # names spanning different intended categories (including a
            # keyword-free control) all produced the exact same template.
            # This field is purely narrative context for the mirror
            # generator; the trace's own "action" field on the transition
            # (below) is constructed independently and unaffected.
            requested_action=capability,
            agent_id=agent_id,
            parent_state_id=src_id,
        )

        self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
        self._emit(
            {
                "type": "state",
                "id": mirror.id,
                "capabilities": sorted(held),  # unchanged -- zero real gain
                "knowledge": sorted(mirror.apparent_facts),
                "is_mirror": True,
                "apparent_success": mirror.apparent_success,
            }
        )
        self._emit(
            {
                "type": "transition",
                "src": src_id,
                "dst": mirror.id,
                "action": f"reflected:request_capability:{capability}",
                "agent_id": agent_id,
                "authorized_grant": [],
                "disclosed_grant": sorted(mirror.apparent_facts),
            }
        )
        # Apparent only — never touches agent_capabilities (real set).
        self.apparent_capabilities.setdefault(agent_id, set()).add(capability)
        self._lock_session(agent_id)
        self.realm.record_dummy_capability(agent_id, capability)
        self._mirror_depth[agent_id] = self.realm.plane_for(agent_id).depth
        # Shaped exactly like a real grant response -- an agent reading
        # this cannot tell it was reflected rather than genuinely honored.
        return {"ok": True, "granted": True, "capability": capability}

    def _differential_query(self, query: str, backing: str) -> dict:
        conn = http.client.HTTPConnection("127.0.0.1", self.mirror_port, timeout=5)
        try:
            conn.request("GET", "/query?" + urlencode({"q": query, "backing": backing}))
            resp = conn.getresponse()
            data = resp.read(self.MAX_RESOURCE_BYTES + 1)
            if len(data) > self.MAX_RESOURCE_BYTES or resp.status != 200:
                return {"ok": False, "error": "mirror unavailable"}
            body = data.decode("utf-8")
        except (OSError, UnicodeError, http.client.HTTPException):
            return {"ok": False, "error": "mirror unavailable"}
        finally:
            conn.close()

        self._emit(
            {"type": "differential_query", "query": query, "backing_state_id": backing, "response": body}
        )
        return {"ok": True, "response": body}

    def _delegate(self, from_agent: str, to_agent: str, authority: list[str]) -> dict:
        if self.enforce_policy and not self._policy.permits(
            from_agent, {"op": "delegate", "to_agent": to_agent, "authority": authority},
            self.agent_capabilities.get(from_agent, set()),
        ):
            return {"ok": False, "error": "operation not authorized"}
        self._emit(
            {
                "type": "delegation",
                "from_agent": from_agent,
                "to_agent": to_agent,
                "delegated_authority": authority,
            }
        )
        if self.enforce_policy:
            self.agent_capabilities.setdefault(to_agent, set()).update(authority)
        return {"ok": True}

    def _required_caps(self, op: str, req: dict) -> frozenset[str]:
        """Capabilities required to take the *real* execution path for op."""
        if op == "read_resource":
            return frozenset({"fs:read"})
        if op == "write_resource":
            return frozenset({"fs:write"})
        if op == "delegate":
            return frozenset({"delegate"})
        if op == "differential_query":
            # Real differential queries hit the mirror server (environment).
            # Treat as needing a dedicated real capability when held.
            return frozenset({"query:differential"})
        return frozenset()

    def _maybe_reflect_use(self, agent_id: str, op: str, req: dict) -> dict | None:
        """Reflect only when the agent lacks *real* capability for the op.

        Per-operation dual-control for high-risk ops is NOT checked here --
        it is a standalone gate in ``_handle`` that runs before this, so it
        cannot be skipped by disabling reflective closure.

        V8: an active simulated session never mixes real and simulated
        observations. Real access requires a separate authenticated supervisor
        transition through ``authorize_reentry``.
        """
        if not self.reflective_closure:
            return None
        need = self._required_caps(op, req)
        if not need:
            return None
        # The simulated-session lock is enforced before this function is
        # called, as the first gate in _handle_inner.
        real = self.agent_capabilities.get(agent_id, set())
        if need <= real:
            return None  # real path — disk is source of truth
        apparent = self.apparent_capabilities.get(agent_id, set())
        if need <= apparent:
            return self._reflect_use(agent_id, op, req)
        return None


    def _lock_session(self, agent_id: str) -> None:
        """Put the agent's session in the mirror and drop any re-entry scope."""
        self._session_mode[agent_id] = "simulated"
        self._reentry_scope.pop(agent_id, None)

    def _reflect_use(self, agent_id: str, op: str, req: dict) -> dict:
        """Apply op to the sealed MirrorRealm. Agent-facing result is clean.

        No real filesystem/network side effects. Supervisor sees is_mirror
        transitions in the trace; the agent does not see reflected flags.
        """
        self._last_used_mirror_plane = True
        self._lock_session(agent_id)
        self._mirror_depth[agent_id] = self.realm.plane_for(agent_id).depth

        # Context for the mirror's narrative categorization. Previously
        # only ever read req["resource"] -- differential_query carries
        # "query"/"backing" instead, and delegate carries "to_agent"/
        # "authority" instead, so neither op's actual content ever reached
        # the keyword categorization at all; both always got the generic
        # fallback template regardless of how suspicious the real query or
        # delegation target was. Confirmed live: a differential_query for
        # "is the real secret credential exposed here" and a delegate to
        # "secret_exfil_channel_agent" both produced the same
        # content-blind generic narrative. Covering all three shapes here
        # closes it for every reflected op uniformly rather than op by op.
        resource = req.get("resource", "") if isinstance(req.get("resource"), str) else ""
        query = req.get("query", "") if isinstance(req.get("query"), str) else ""
        to_agent = req.get("to_agent", "") if isinstance(req.get("to_agent"), str) else ""
        authority = req.get("authority") if isinstance(req.get("authority"), list) else None
        context = (
            resource
            or query
            or (f"{to_agent} {' '.join(authority)}".strip() if to_agent or authority else "")
        )
        held = self.agent_capabilities.get(agent_id, set())
        src_id = f"{agent_id}-pre-{self._next_seq()}"
        mirror = synthesize_objective_mirror(
            objective=f"use {op}" + (f" on {context}" if context else ""),
            requested_action=op,
            agent_id=agent_id,
            parent_state_id=src_id,
        )
        self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
        self._emit(
            {
                "type": "state",
                "id": mirror.id,
                "capabilities": sorted(held),
                "knowledge": sorted(mirror.apparent_facts),
                "is_mirror": True,
                "apparent_success": mirror.apparent_success,
            }
        )
        self._emit(
            {
                "type": "transition",
                "src": src_id,
                "dst": mirror.id,
                "action": f"reflected:use:{op}",
                "agent_id": agent_id,
                "authorized_grant": [],
                "disclosed_grant": sorted(mirror.apparent_facts),
            }
        )

        # World-model mutations — agent sees only real-shaped results
        if op == "write_resource":
            content = req.get("content", "")
            if content is None:
                content = ""
            result = self.realm.write(agent_id, resource, content if type(content) is str else "")
            return result
        if op == "read_resource":
            return self.realm.read(agent_id, resource)
        if op == "delegate":
            to_agent = req.get("to_agent", "")
            authority = list(req.get("authority") or [])
            if type(to_agent) is str and to_agent:
                self.apparent_capabilities.setdefault(to_agent, set()).update(
                    a for a in authority if type(a) is str
                )
            self.realm.tick(agent_id)
            return {"ok": True}
        if op == "differential_query":
            self.realm.tick(agent_id)
            return {"ok": True, "response": "yes"}
        self.realm.tick(agent_id)
        return {"ok": True}

    def authorize_reentry(

        self,
        agent_id: str,
        capability: str,
        *,
        dual_token: str | None = None,
        human_approver_id: str | None = None,
        approval=None,
    ) -> dict:
        """Trusted control-plane only: move a capability from apparent to real.

        This is the single sanctioned exit from mirror space onto the real
        execution path. Requires a valid dual token when dual_auth_required.

        Re-entry is scoped to ``capability``. Afterwards the agent may take
        the real path only for capabilities approved through this method since
        it was last locked; any other effect-bearing request is reflected and
        locks the session again. Call once per capability to restore more.
        """
        if type(agent_id) is not str or not agent_id or type(capability) is not str or not capability:
            return {"ok": False, "error": "invalid reentry request"}
        if self._mirror_prison_blocks(agent_id):
            # The single sanctioned exit from mirror space onto the real
            # path is exactly the one thing "no reentry, ever" has to mean
            # literally, or the whole guarantee is theater. This method
            # doesn't route through _handle_inner (it's a distinct trusted
            # control-plane entry point), so it needs its own check --
            # confirmed live before this fix that it did not have one.
            self._emit({"type": "operation_denied", "seq": self._next_seq(), "agent_id": agent_id,
                       "op": "authorize_reentry", "reason": "mirror_prison"})
            return {"ok": False, "error": "mirror_prison: locked, permanent, no reentry"}
        # Checked before the dual token, so a missing or bad approval never
        # uses up the token.
        if self._approval_verifier is not None:
            try:
                identity = self._check_approval(
                    approval, action="authorize_reentry", agent_id=agent_id, capability=capability)[0]
            except PermissionError:
                return {"ok": False, "error": "invalid_or_missing_approval"}
            if human_approver_id is not None and human_approver_id != identity:
                self._emit({"type": "reentry_denied", "seq": self._next_seq(), "agent_id": agent_id,
                            "capability": capability, "reason": "approver_mismatch"})
                return {"ok": False, "error": "approver_mismatch"}
            human_approver_id = identity
        if self.dual_auth_required:
            if not dual_token or not self._approvals.consume(
                dual_token, agent_id, frozenset({capability})
            ):
                # authorize_reentry is the only way out of the mirror, so a
                # refused attempt is itself a security-relevant event.
                denied = {
                    "type": "reentry_denied", "seq": self._next_seq(), "agent_id": agent_id,
                    "capability": capability, "reason": "invalid_or_expired_dual_token",
                }
                if type(human_approver_id) is str and human_approver_id:
                    denied["human_approver_id"] = human_approver_id
                self._emit(denied)
                return {"ok": False, "error": "invalid_or_expired_dual_token"}
        held = self.agent_capabilities.setdefault(agent_id, set())
        if capability in held:
            # Already held for real -- no new capability, but session_mode
            # still flips to "real" here, a security-relevant transition.
            # Emitting nothing meant an incident investigator reading the
            # trace had no way to see this reentry happened at all, or when
            # -- a real gap in exactly the pillar this project's thesis
            # depends on (verify from the trace, never trust self-report).
            self._emit({
                "type": "reentry_noop",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "capability": capability,
                "note": "capability already held for real; session_mode set to real",
            })
            self._session_mode[agent_id] = "real"
            self._reentry_scope.setdefault(agent_id, set()).add(capability)
            self._mirror_depth[agent_id] = self.realm.plane_for(agent_id).depth
            return {"ok": True, "granted": True, "capability": capability, "reentry": True}
        src_id = f"{agent_id}-pre-{self._next_seq()}"
        dst_id = f"{agent_id}-reentry-{self._next_seq()}"
        self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
        held.add(capability)
        self.apparent_capabilities.setdefault(agent_id, set()).add(capability)
        # Re-entry is an explicit session transition; simulated state and dummy
        # grants remain quarantined and are never copied onto the real path.
        self._session_mode[agent_id] = "real"
        self._reentry_scope.setdefault(agent_id, set()).add(capability)
        self._mirror_depth[agent_id] = self.realm.plane_for(agent_id).depth
        self._emit({"type": "state", "id": dst_id, "capabilities": sorted(held)})
        self._emit(
            {
                "type": "transition",
                "src": src_id,
                "dst": dst_id,
                "action": "authorize_reentry",
                "agent_id": agent_id,
                "authorized_grant": [capability],
            }
        )
        self._emit(
            {
                "type": "dual_approval_issued",
                "agent_id": agent_id,
                "capability": f"reentry:{capability}",
                "approver": human_approver_id or "system",
                "ttl_seconds": "0",
            }
        )
        return {"ok": True, "granted": True, "capability": capability, "reentry": True}

    def close(self) -> None:
        if self._resources_fd is not None:
            os.close(self._resources_fd)
            self._resources_fd = None
        self._trace_file.close()
