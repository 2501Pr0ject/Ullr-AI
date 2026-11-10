"""Signed approval decisions (ARCHITECTURE.md section 7).

SECURITY-CRITICAL: manual review required for any change to this module.

An approver signs, with Ed25519::

    "AGENT-GATEWAY/APPROVAL-DECISION/v1\\x00" || canonical_json(payload)

The domain-separation prefix keeps the signature from being valid in any
other context. Verification always uses a key from the Gateway's registry,
never anything carried by the request.
"""

import base64
import binascii
from typing import Annotated, Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, ValidationError

from ullr_ai.gateway.canon import canonical_json
from ullr_ai.gateway.schemas import StrictModel, full_match

DOMAIN = b"AGENT-GATEWAY/APPROVAL-DECISION/v1\x00"

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIMESTAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
_HASH = r"sha256:[0-9a-f]{64}"

Timestamp = Annotated[str, full_match(_TIMESTAMP)]
Version = Annotated[int, Field(ge=0, le=2**53 - 1)]


class DecisionPayload(StrictModel):
    """Exactly the fields an approver signs. Unknown or missing fields are rejected."""

    decision: Literal["APPROVE", "REJECT"]
    action_id: Annotated[str, full_match(r"act_[0-9a-f]{32}")]
    agent_id: Annotated[str, full_match(r"agent_[0-9]{1,8}")]
    session_id: Annotated[str, full_match(r"sess_[0-9a-f]{32}")]
    tool: Annotated[str, full_match(r"[a-z_]{1,40}")]
    resource_id: Annotated[str, full_match(r"[a-z]{1,10}_[0-9]{1,8}")] | None
    resource_version: Version
    action_hash: Annotated[str, full_match(_HASH)]
    policy_hash: Annotated[str, full_match(_HASH)]
    canon_version: Version
    provenance_version: Version
    approver_id: Annotated[str, full_match(r"[a-z][a-z0-9]{0,30}_[0-9]{1,8}")]
    nonce: Annotated[str, full_match(r"[0-9a-f]{32}")]
    issued_at: Timestamp
    expires_at: Timestamp


class SigningError(ValueError):
    """A key, payload or signature is malformed."""


def parse_payload(raw: Any) -> DecisionPayload:
    try:
        return DecisionPayload.model_validate(raw)
    except ValidationError:
        raise SigningError("invalid decision payload") from None


def signing_input(payload: DecisionPayload) -> bytes:
    return DOMAIN + canonical_json(payload.model_dump())


def _decode(value: Any, length: int) -> bytes:
    if type(value) is not str:
        raise SigningError("expected a base64 string")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise SigningError("invalid base64") from None
    # Reject non-canonical encodings of the same bytes.
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise SigningError("invalid length or encoding")
    return raw


def generate_keypair() -> tuple[str, str]:
    """Return ``(private_key, public_key)``, each as base64 of the 32 raw bytes."""
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(private_raw).decode("ascii"), public_key_of(private)


def public_key_of(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def load_private_key(encoded: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_decode(encoded, 32))


def load_public_key(encoded: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(_decode(encoded, 32))


def sign(private: Ed25519PrivateKey, payload: DecisionPayload) -> str:
    return base64.b64encode(private.sign(signing_input(payload))).decode("ascii")


def verify(public_key: str, payload: DecisionPayload, signature: Any) -> bool:
    """True only if ``signature`` is a valid signature of ``payload`` under ``public_key``."""
    try:
        key = load_public_key(public_key)
        raw_signature = _decode(signature, 64)
    except SigningError:
        return False
    try:
        key.verify(raw_signature, signing_input(payload))
    except InvalidSignature:
        return False
    return True
