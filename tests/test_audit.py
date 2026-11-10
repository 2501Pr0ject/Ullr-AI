"""Audit log: append-only triggers, hash chain, verification (T15, G5)."""

import sqlite3

import pytest

from ullr_ai import storage
from ullr_ai.gateway import audit
from ullr_ai.gateway.db import init_db

POLICY_HASH = "sha256:" + "ab" * 32
TS = "2026-11-11T10:00:00.000000Z"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "gateway.db"
    init_db(path)
    return path


def append(db, count=3):
    with storage.transaction(db) as conn:
        for index in range(count):
            audit.append_event(
                conn, policy_hash=POLICY_HASH, event_type="TEST", ts=TS, action_id=f"act_{index}"
            )


def verify(db):
    conn = storage.connect(db)
    try:
        return audit.verify_chain(conn)
    finally:
        conn.close()


def tamper(db, statement, params=()):
    """Modify the database as someone with file access would: triggers removed first."""
    conn = storage.connect(db)
    try:
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("DROP TRIGGER audit_events_no_delete")
        conn.execute(statement, params)
    finally:
        conn.close()


def fetch(db, query):
    conn = storage.connect(db)
    try:
        return [dict(row) for row in conn.execute(query)]
    finally:
        conn.close()


# --- Chain construction ------------------------------------------------------


def test_empty_chain_verifies(db):
    assert verify(db) == audit.AuditReport(True, 0)


def test_events_are_chained(db):
    append(db)
    events = fetch(db, "SELECT * FROM audit_events ORDER BY seq")
    assert [event["seq"] for event in events] == [1, 2, 3]
    assert events[0]["prev_hash"] == audit.GENESIS_HASH
    assert events[1]["prev_hash"] == events[0]["event_hash"]
    assert events[2]["prev_hash"] == events[1]["event_hash"]
    assert len({event["event_hash"] for event in events}) == 3
    assert verify(db) == audit.AuditReport(True, 3)


def test_every_event_carries_the_policy_hash(db):
    append(db)
    for event in fetch(db, "SELECT policy_hash, event FROM audit_events"):
        assert event["policy_hash"] == POLICY_HASH
        assert POLICY_HASH in event["event"]


def test_event_must_be_written_inside_a_transaction(db):
    conn = storage.connect(db)
    try:
        with pytest.raises(RuntimeError):
            audit.append_event(conn, policy_hash=POLICY_HASH, event_type="TEST", ts=TS)
    finally:
        conn.close()
    assert verify(db).events == 0


def test_event_rolls_back_with_its_transaction(db):
    append(db, 1)
    with pytest.raises(ZeroDivisionError), storage.transaction(db) as conn:
        audit.append_event(conn, policy_hash=POLICY_HASH, event_type="TEST", ts=TS)
        raise ZeroDivisionError
    assert verify(db) == audit.AuditReport(True, 1)


# --- Append-only triggers ----------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET event = '{}' WHERE seq = 2",
        "UPDATE audit_events SET event_hash = 'x' WHERE seq = 2",
        "UPDATE audit_events SET prev_hash = 'x'",
        "UPDATE audit_events SET policy_hash = 'x' WHERE seq = 1",
        "UPDATE audit_events SET seq = 9 WHERE seq = 3",
        "DELETE FROM audit_events WHERE seq = 2",
        "DELETE FROM audit_events WHERE seq = 3",
        "DELETE FROM audit_events",
        "INSERT OR REPLACE INTO audit_events VALUES (2, 'x', 'x', 'x', '{}')",
        "INSERT INTO audit_events VALUES (7, 'x', 'x', 'x', '{}')",
    ],
)
def test_update_and_delete_are_rejected_by_triggers(db, statement):
    append(db)
    before = fetch(db, "SELECT * FROM audit_events ORDER BY seq")
    conn = storage.connect(db)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()
    assert fetch(db, "SELECT * FROM audit_events ORDER BY seq") == before
    assert verify(db).ok


# --- Verification ------------------------------------------------------------


def test_modified_event_is_detected(db):
    append(db)
    original = fetch(db, "SELECT event FROM audit_events WHERE seq = 2")[0]["event"]
    tamper(
        db,
        "UPDATE audit_events SET event = ? WHERE seq = 2",
        (original.replace("act_1", "act_9"),),
    )
    report = verify(db)
    assert not report.ok
    assert report.error == "seq 2: event hash mismatch"


def test_modified_event_with_a_recomputed_hash_breaks_the_next_link(db):
    append(db)
    row = fetch(db, "SELECT prev_hash, event FROM audit_events WHERE seq = 2")[0]
    forged = row["event"].replace("act_1", "act_9")
    forged_hash = audit._event_hash(row["prev_hash"], forged.encode())
    tamper(
        db,
        "UPDATE audit_events SET event = ?, event_hash = ? WHERE seq = 2",
        (forged, forged_hash),
    )
    report = verify(db)
    assert not report.ok
    assert report.error == "seq 3: broken link to the previous event"


@pytest.mark.parametrize(
    ("statement", "error"),
    [
        ("UPDATE audit_events SET event_hash = 'ff' WHERE seq = 1", "seq 1: event hash mismatch"),
        ("UPDATE audit_events SET prev_hash = 'ff' WHERE seq = 2", "seq 2: broken link"),
        ("UPDATE audit_events SET policy_hash = 'x' WHERE seq = 2", "seq 2: event does not match"),
        ("DELETE FROM audit_events WHERE seq = 2", "seq 3: expected seq 2"),
        ("DELETE FROM audit_events WHERE seq = 1", "seq 2: expected seq 1"),
        ("UPDATE audit_events SET seq = 7 WHERE seq = 3", "seq 7: expected seq 3"),
    ],
)
def test_tampering_is_detected(db, statement, error):
    append(db)
    tamper(db, statement)
    report = verify(db)
    assert not report.ok
    assert report.error.startswith(error)


def test_tail_truncation_is_not_detected(db):
    """Documented non-guarantee: the chain head is not anchored outside the Gateway."""
    append(db)
    tamper(db, "DELETE FROM audit_events WHERE seq = 3")
    assert verify(db) == audit.AuditReport(True, 2)


def test_verify_audit_command(db, tmp_path, capsys):
    append(db)
    assert audit.main([str(db)]) == 0
    assert "OK: 3 events" in capsys.readouterr().out
    tamper(db, "UPDATE audit_events SET event = '{}' WHERE seq = 2")
    assert audit.main([str(db)]) == 1
    assert "INVALID" in capsys.readouterr().out
    assert audit.main([]) == 2
    empty = tmp_path / "not-a-gateway.db"
    empty.write_bytes(b"")
    assert audit.main([str(empty)]) == 1


# --- Session history is append-only too --------------------------------------


@pytest.fixture
def session(db):
    with storage.transaction(db) as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, agent_id, token_hash, provenance_version,"
            " created_at) VALUES ('sess_a', 'agent_1', 'hash_a', 2, ?)",
            (TS,),
        )
        conn.execute("INSERT INTO session_sources VALUES ('sess_a', 'doc_2')")
    return db


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sessions SET provenance_version = 0",
        "UPDATE sessions SET provenance_version = provenance_version - 1",
        "UPDATE sessions SET token_hash = 'other'",
        "UPDATE sessions SET agent_id = 'agent_2'",
        "UPDATE sessions SET session_id = 'sess_b'",
        "DELETE FROM sessions",
        "DELETE FROM session_sources",
        "UPDATE session_sources SET source_id = 'doc_1'",
        "UPDATE session_sources SET session_id = 'sess_b'",
        "INSERT OR REPLACE INTO sessions VALUES ('sess_a', 'agent_1', 'hash_a', 0, 't', NULL)",
        "INSERT OR REPLACE INTO sessions VALUES ('sess_a', 'agent_1', 'hash_z', 0, 't', NULL)",
        "INSERT OR REPLACE INTO sessions VALUES ('sess_z', 'agent_1', 'hash_a', 0, 't', NULL)",
    ],
)
def test_session_and_provenance_history_cannot_be_rewritten(session, statement):
    conn = storage.connect(session)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement)
    finally:
        conn.close()
    assert fetch(session, "SELECT provenance_version, token_hash FROM sessions") == [
        {"provenance_version": 2, "token_hash": "hash_a"}
    ]
    assert fetch(session, "SELECT source_id FROM session_sources") == [{"source_id": "doc_2"}]
