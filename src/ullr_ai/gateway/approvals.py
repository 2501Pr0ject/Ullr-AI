"""Approver registry, approval records and the checks applied to a signed decision.

An approval binds one action to: action hash, resource version, policy hash,
canon version, provenance version, a Gateway-generated nonce and an expiry
(ARCHITECTURE.md section 7). The checks here are pure; state transitions are
made by the Gateway inside its transactions.
"""

import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ullr_ai.gateway import provenance, signing
from ullr_ai.gateway.policy import TOOL_TIERS, load_yaml_strict

_AGENT_ID = re.compile(r"agent_[0-9]{1,8}")
_APPROVER_ID = re.compile(r"[a-z][a-z0-9]{0,30}_[0-9]{1,8}")

# Fields of the signed payload that must equal the stored record exactly.
BOUND_FIELDS = (
    "action_id",
    "agent_id",
    "session_id",
    "tool",
    "resource_id",
    "resource_version",
    "action_hash",
    "policy_hash",
    "canon_version",
    "provenance_version",
    "nonce",
)


class RegistryError(ValueError):
    """The approver registry cannot be loaded."""


class DecisionError(Exception):
    """A submitted decision is not acceptable. Carries no detail on purpose."""


def is_agent_principal(principal_id: str) -> bool:
    return _AGENT_ID.fullmatch(principal_id) is not None


def validate_registry(approvers: Any) -> dict[str, str]:
    """Check an ``approver_id -> base64 public key`` mapping. Fails on any defect."""
    if type(approvers) is not dict:
        raise RegistryError("approvers must be a mapping")
    for approver_id, public_key in approvers.items():
        if type(approver_id) is not str or _APPROVER_ID.fullmatch(approver_id) is None:
            raise RegistryError("invalid approver id")
        if is_agent_principal(approver_id):
            raise RegistryError("an agent principal cannot be an approver")
        try:
            signing.load_public_key(public_key)
        except (signing.SigningError, ValueError):
            raise RegistryError("invalid approver public key") from None
    return dict(approvers)


def load_registry(path: Path | str) -> dict[str, str]:
    """Load the approver registry file: ``approvers: {approver_id: public_key}``."""
    try:
        data = load_yaml_strict(Path(path).read_bytes())
    except OSError:
        raise RegistryError("approver registry cannot be read") from None
    except ValueError:
        raise RegistryError("approver registry is not valid YAML") from None
    if type(data) is not dict or set(data) != {"approvers"}:
        raise RegistryError("approver registry must contain exactly 'approvers'")
    return validate_registry(data["approvers"])


def create(conn: sqlite3.Connection, action_id: str, now: datetime, ttl_seconds: int) -> str:
    """Create the approval record of a pending action. Returns its expiry."""
    expires_at = (now + timedelta(seconds=ttl_seconds)).strftime(signing.TIMESTAMP_FORMAT)
    conn.execute(
        "INSERT INTO approvals (action_id, nonce, expires_at) VALUES (?, ?, ?)",
        (action_id, secrets.token_hex(16), expires_at),
    )
    return expires_at


def record_of(conn: sqlite3.Connection, action_id: str) -> dict[str, Any] | None:
    """The action joined with its approval record, or None."""
    row = conn.execute(
        "SELECT a.*, p.nonce, p.expires_at, p.approver_id, p.decision, p.signature, p.payload"
        " FROM actions a JOIN approvals p USING (action_id) WHERE a.action_id = ?",
        (action_id,),
    ).fetchone()
    return None if row is None else dict(row)


def check_decision(
    record: dict[str, Any], raw_payload: Any, signature: Any, registry: dict[str, str]
) -> signing.DecisionPayload:
    """Accept a decision only if every condition of ARCHITECTURE.md section 7 holds.

    The verification key comes from the registry, looked up by the approver id
    the payload claims: a payload cannot bring its own key.
    """
    try:
        payload = signing.parse_payload(raw_payload)
    except signing.SigningError:
        raise DecisionError from None
    for field in BOUND_FIELDS:
        if getattr(payload, field) != record[field]:
            raise DecisionError
    if payload.expires_at > record["expires_at"]:
        raise DecisionError
    public_key = registry.get(payload.approver_id)
    if public_key is None or is_agent_principal(payload.approver_id):
        raise DecisionError
    if not signing.verify(public_key, payload, signature):
        raise DecisionError
    return payload


def request_view(conn: sqlite3.Connection, record: dict[str, Any]) -> dict[str, Any]:
    """What an approver is shown, and the fields they must sign.

    Provenance comes from the Gateway's own observations. The agent's reason is
    carried under a name that says what it is: an unverified statement.
    """
    observed = provenance.snapshot(conn, record["session_id"])
    return {
        "request": {field: record[field] for field in BOUND_FIELDS}
        | {"expires_at": record["expires_at"]},
        "tier": TOOL_TIERS[record["tool"]],
        "args": json.loads(record["args"]),
        "agent_reason_unverified": record["reason"],
        "created_at": record["created_at"],
        "provenance": {
            "tainted": observed.tainted,
            "version": observed.version,
            "external_sources": list(observed.sources),
        },
    }
