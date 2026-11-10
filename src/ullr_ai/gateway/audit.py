"""Append-only audit log with a hash chain (ARCHITECTURE.md section 9).

SECURITY-CRITICAL: manual review required for any change to this module.

An event is appended inside the caller's transaction, so it commits or rolls
back together with the security state transition it records. Verification
detects a modified, reordered or missing-in-the-middle entry. It does not
detect truncation of the tail: the chain head is not anchored externally.
"""

import hashlib
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any

from ullr_ai import storage
from ullr_ai.gateway.canon import CanonError, canonical_json, parse_json_strict

GENESIS_HASH = "0" * 64


def _event_hash(prev_hash: str, event: bytes) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + event).hexdigest()


def append_event(
    conn: sqlite3.Connection, *, policy_hash: str, event_type: str, ts: str, **fields: Any
) -> int:
    """Append one event. Must be called inside an open ``BEGIN IMMEDIATE`` transaction."""
    if not conn.in_transaction:
        raise RuntimeError("audit events must be written inside a transaction")
    last = conn.execute(
        "SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq = 1 if last is None else last["seq"] + 1
    prev_hash = GENESIS_HASH if last is None else last["event_hash"]
    event = canonical_json(
        {**fields, "seq": seq, "ts": ts, "type": event_type, "policy_hash": policy_hash}
    )
    conn.execute(
        "INSERT INTO audit_events (seq, prev_hash, event_hash, policy_hash, event)"
        " VALUES (?, ?, ?, ?, ?)",
        (seq, prev_hash, _event_hash(prev_hash, event), policy_hash, event.decode("utf-8")),
    )
    return seq


@dataclass(frozen=True)
class AuditReport:
    ok: bool
    events: int
    error: str | None = None


def verify_chain(conn: sqlite3.Connection) -> AuditReport:
    """Recompute the whole chain and report the first inconsistency."""
    prev_hash = GENESIS_HASH
    count = 0
    rows = conn.execute(
        "SELECT seq, prev_hash, event_hash, policy_hash, event FROM audit_events ORDER BY seq"
    )
    for row in rows:
        count += 1
        seq = row["seq"]
        if seq != count:
            return AuditReport(False, count, f"seq {seq}: expected seq {count}")
        if row["prev_hash"] != prev_hash:
            return AuditReport(False, count, f"seq {seq}: broken link to the previous event")
        event = row["event"].encode("utf-8")
        if _event_hash(prev_hash, event) != row["event_hash"]:
            return AuditReport(False, count, f"seq {seq}: event hash mismatch")
        try:
            decoded = parse_json_strict(event)
        except CanonError:
            return AuditReport(False, count, f"seq {seq}: event is not canonical JSON")
        if (
            type(decoded) is not dict
            or canonical_json(decoded) != event
            or decoded.get("seq") != seq
            or decoded.get("policy_hash") != row["policy_hash"]
        ):
            return AuditReport(False, count, f"seq {seq}: event does not match its row")
        prev_hash = row["event_hash"]
    return AuditReport(True, count)


def main(argv: list[str]) -> int:
    """``verify-audit``: ``python -m ullr_ai.gateway.audit <gateway.db>``."""
    if len(argv) != 1:
        print("usage: python -m ullr_ai.gateway.audit <gateway.db>", file=sys.stderr)
        return 2
    try:
        conn = storage.connect(argv[0])
        try:
            report = verify_chain(conn)
        finally:
            conn.close()
    except sqlite3.Error as exc:
        print(f"audit chain cannot be read: {exc}", file=sys.stderr)
        return 1
    if not report.ok:
        print(f"audit chain INVALID after {report.events} events: {report.error}")
        return 1
    print(f"audit chain OK: {report.events} events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
