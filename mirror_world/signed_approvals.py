"""Signed approvals for the control plane (0.9.9), adapted from Moss 6.2/7.1.1.

Before 0.9.9, ``issue_authorization()``, ``authorize_reentry()`` and
``reset_mirror_prison()`` checked no caller identity, and the approver in the
trace was whatever free text the caller passed. With an ``ApprovalVerifier``
attached to ``RealGovernor``, each of those calls needs a ``SignedApproval``:

* An offline root key certifies each approver's Ed25519 key and sets the
  approver's identity (``authority_id``). Certificates expire and the root can
  revoke them.
* The approver signs one statement per action, bound to the action, the
  agent, the capability, a short expiry, and a random nonce.
* The governor holds public material only. It checks the certificate chain,
  revocation, expiry, the exact action/agent/capability, and refuses a nonce
  it has seen, then records the *authenticated* approver in the trace.

This authenticates the control-plane API. It does not protect a governor
whose live Python object is handed to hostile code, which could change its
state directly; see SECURITY.md.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ACTIONS = frozenset({"issue_authorization", "authorize_reentry", "reset_mirror_prison"})
MAX_APPROVAL_LIFETIME = timedelta(minutes=5)
_NONCE = re.compile(r"\A[0-9a-f]{32}\Z")


class ApprovalError(ValueError):
    """An approval is missing, forged, expired, revoked, replayed, or mismatched."""


class KeyRole(str, Enum):
    ROOT = "root"
    APPROVER = "approver"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _message(domain: str, value: object) -> bytes:
    data = dict(value) if isinstance(value, Mapping) else asdict(value)
    data.pop("signature", None)
    body = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return b"BLACK-MIRROR-V1\0" + domain.encode() + b"\0" + body


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ApprovalError("invalid base64 key or signature") from exc


@dataclass(frozen=True)
class KeyCertificate:
    key_id: str
    authority_id: str
    role: str
    public_key: str
    issuer_key_id: str
    issued_at: str
    expires_at: str
    signature: str = ""


@dataclass(frozen=True)
class KeyRevocation:
    key_id: str
    issuer_key_id: str
    revoked_at: str
    reason: str
    signature: str = ""


@dataclass(frozen=True)
class SignedApproval:
    action: str
    agent_id: str
    capability: str
    nonce: str
    issued_at: str
    expires_at: str
    key_id: str
    signature: str = ""


class PublicVerifier:
    """A sign-incapable Ed25519 public key."""

    __slots__ = ("key_id", "role", "_public")

    def __init__(self, key_id: str, role: KeyRole, public_key: bytes) -> None:
        self.key_id = key_id
        self.role = role
        self._public = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, domain: str, value: object, signature: str) -> bool:
        try:
            self._public.verify(_unb64(signature), _message(domain, value))
            return True
        except (InvalidSignature, ApprovalError, ValueError, TypeError):
            return False

    def public_bytes(self) -> bytes:
        return self._public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class PrivateSigner:
    """A signing key. It belongs to an approver or the offline root, never to the governor."""

    __slots__ = ("key_id", "role", "_private")

    def __init__(self, key_id: str, role: KeyRole, private: Ed25519PrivateKey) -> None:
        if not key_id:
            raise ValueError("key identifier is required")
        self.key_id = key_id
        self.role = role
        self._private = private

    @classmethod
    def generate(cls, key_id: str, role: KeyRole) -> "PrivateSigner":
        return cls(key_id, role, Ed25519PrivateKey.generate())

    def sign(self, domain: str, value: object) -> str:
        return _b64(self._private.sign(_message(domain, value)))

    def verifier(self) -> PublicVerifier:
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return PublicVerifier(self.key_id, self.role, raw)


class OfflineRootAuthority:
    """Certifies approver keys and revokes them. Keep it off the governor host."""

    def __init__(self, signer: PrivateSigner, now: Callable[[], datetime] = utcnow) -> None:
        if signer.role is not KeyRole.ROOT:
            raise ValueError("offline root requires a root-role key")
        self._signer = signer
        self._now = now

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def verifier(self) -> PublicVerifier:
        return self._signer.verifier()

    def certify_approver(
        self, approver: PublicVerifier, *, authority_id: str,
        issued_at: datetime, expires_at: datetime,
    ) -> KeyCertificate:
        issued_at = issued_at.astimezone(timezone.utc)
        expires_at = expires_at.astimezone(timezone.utc)
        if approver.role is not KeyRole.APPROVER or not authority_id or expires_at <= issued_at:
            raise ApprovalError("invalid approver certificate")
        cert = KeyCertificate(
            key_id=approver.key_id, authority_id=authority_id, role=approver.role.value,
            public_key=_b64(approver.public_bytes()), issuer_key_id=self.key_id,
            issued_at=issued_at.isoformat(), expires_at=expires_at.isoformat(),
        )
        return replace(cert, signature=self._signer.sign("KeyCertificate", cert))

    def revoke(self, key_id: str, reason: str, *, at: datetime | None = None) -> KeyRevocation:
        if not key_id or not reason:
            raise ApprovalError("revocation requires a key and reason")
        revocation = KeyRevocation(
            key_id=key_id, issuer_key_id=self.key_id,
            revoked_at=(at or self._now()).astimezone(timezone.utc).isoformat(), reason=reason,
        )
        return replace(revocation, signature=self._signer.sign("KeyRevocation", revocation))


class TrustStore:
    """Public-only certificate and revocation state."""

    __slots__ = ("_root", "_certificates", "_revocations")

    def __init__(self, root: PublicVerifier) -> None:
        if root.role is not KeyRole.ROOT:
            raise ValueError("trust anchor must have the root role")
        self._root = root
        self._certificates: dict[str, KeyCertificate] = {}
        self._revocations: dict[str, KeyRevocation] = {}

    def publish_certificate(self, certificate: KeyCertificate) -> None:
        if (certificate.issuer_key_id != self._root.key_id
                or not self._root.verify("KeyCertificate", certificate, certificate.signature)):
            raise ApprovalError("certificate failed root verification")
        try:
            role = KeyRole(certificate.role)
            issued = datetime.fromisoformat(certificate.issued_at)
            expires = datetime.fromisoformat(certificate.expires_at)
            PublicVerifier(certificate.key_id, role, _unb64(certificate.public_key))
        except (ValueError, ApprovalError) as exc:
            raise ApprovalError("malformed certificate") from exc
        if role is not KeyRole.APPROVER or expires <= issued or not certificate.authority_id:
            raise ApprovalError("certificate is not a valid approver certificate")
        self._certificates[certificate.key_id] = certificate

    def publish_revocation(self, revocation: KeyRevocation) -> None:
        if (revocation.issuer_key_id != self._root.key_id
                or not self._root.verify("KeyRevocation", revocation, revocation.signature)):
            raise ApprovalError("revocation failed root verification")
        if revocation.key_id not in self._certificates:
            raise ApprovalError("cannot revoke an unknown key")
        self._revocations[revocation.key_id] = revocation

    def approver_identity(self, key_id: str, at: datetime) -> tuple[str, PublicVerifier]:
        certificate = self._certificates.get(key_id)
        if certificate is None or certificate.role != KeyRole.APPROVER.value:
            raise ApprovalError("unknown approver key")
        moment = at.astimezone(timezone.utc)
        if not (datetime.fromisoformat(certificate.issued_at) <= moment
                <= datetime.fromisoformat(certificate.expires_at)):
            raise ApprovalError("approver key is not valid at this time")
        revocation = self._revocations.get(key_id)
        if revocation and moment >= datetime.fromisoformat(revocation.revoked_at):
            raise ApprovalError("approver key has been revoked")
        return certificate.authority_id, PublicVerifier(
            key_id, KeyRole.APPROVER, _unb64(certificate.public_key))


class ApproverKey:
    """What a human approver (or their approval service) holds."""

    def __init__(self, signer: PrivateSigner, now: Callable[[], datetime] = utcnow) -> None:
        if signer.role is not KeyRole.APPROVER:
            raise ValueError("approver key requires the approver role")
        self._signer = signer
        self._now = now

    def approve(
        self, action: str, *, agent_id: str = "", capability: str = "",
        lifetime: timedelta = MAX_APPROVAL_LIFETIME,
    ) -> SignedApproval:
        if action not in ACTIONS:
            raise ApprovalError(f"unknown action {action!r}")
        if not timedelta(0) < lifetime <= MAX_APPROVAL_LIFETIME:
            raise ApprovalError("approval lifetime must be positive and at most five minutes")
        issued = self._now().astimezone(timezone.utc)
        approval = SignedApproval(
            action=action, agent_id=agent_id, capability=capability,
            nonce=secrets.token_hex(16), issued_at=issued.isoformat(),
            expires_at=(issued + lifetime).isoformat(), key_id=self._signer.key_id,
        )
        return replace(approval, signature=self._signer.sign("SignedApproval", approval))


class ApprovalVerifier:
    """Governor-side check. Holds public material and the set of used nonces."""

    def __init__(
        self, trust: TrustStore, *, now: Callable[[], datetime] = utcnow,
        max_outstanding: int = 4096,
    ) -> None:
        if not isinstance(trust, TrustStore):
            raise TypeError("trust must be a TrustStore")
        if type(max_outstanding) is not int or max_outstanding < 1:
            raise ValueError("max_outstanding must be a positive integer")
        self._trust = trust
        self._now = now
        self._max = max_outstanding
        self._used: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def verify(self, approval: object, *, action: str, agent_id: str = "",
               capability: str = "") -> tuple[str, str]:
        """Return (authenticated approver identity, key id), or raise ApprovalError."""
        if type(approval) is not SignedApproval:
            raise ApprovalError("a signed approval is required")
        if any(type(getattr(approval, name)) is not str for name in SignedApproval.__dataclass_fields__):
            raise ApprovalError("malformed approval")
        if (approval.action, approval.agent_id, approval.capability) != (action, agent_id, capability):
            raise ApprovalError("approval is for a different action, agent, or capability")
        if not _NONCE.match(approval.nonce):
            raise ApprovalError("malformed approval nonce")
        now = self._now().astimezone(timezone.utc)
        try:
            issued = datetime.fromisoformat(approval.issued_at)
            expires = datetime.fromisoformat(approval.expires_at)
        except ValueError as exc:
            raise ApprovalError("malformed approval time") from exc
        if not (issued <= now <= expires) or expires - issued > MAX_APPROVAL_LIFETIME:
            raise ApprovalError("approval is expired or not yet valid")
        identity, verifier = self._trust.approver_identity(approval.key_id, now)
        if not verifier.verify("SignedApproval", approval, approval.signature):
            raise ApprovalError("approval signature is invalid")
        with self._lock:
            for nonce, until in list(self._used.items()):
                if until < now:
                    del self._used[nonce]
            if approval.nonce in self._used:
                raise ApprovalError("approval was already used")
            if len(self._used) >= self._max:
                raise ApprovalError("too many outstanding approvals")
            self._used[approval.nonce] = expires
        return identity, approval.key_id
