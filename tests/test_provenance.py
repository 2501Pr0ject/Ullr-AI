"""Session provenance derived from observed trust labels only (T12, G6)."""

import pytest

from ullr_ai import storage
from ullr_ai.gateway import provenance
from ullr_ai.gateway.db import init_db


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "gateway.db"
    init_db(path)
    with storage.transaction(path) as conn:
        for session_id in ("sess_a", "sess_b"):
            conn.execute(
                "INSERT INTO sessions (session_id, agent_id, token_hash, created_at)"
                " VALUES (?, 'agent_1', ?, '2026-11-11T10:00:00Z')",
                (session_id, "hash_" + session_id),
            )
    return path


def record(db, session_id, sources):
    with storage.transaction(db) as conn:
        return provenance.record_sources(conn, session_id, sources)


def state(db, session_id):
    with storage.transaction(db) as conn:
        return provenance.snapshot(conn, session_id)


def test_new_session_is_clean(db):
    assert state(db, "sess_a") == provenance.Provenance(0, ())
    assert not state(db, "sess_a").tainted


def test_internal_sources_do_not_taint(db):
    assert record(db, "sess_a", [("doc_1", "internal"), ("acct_1", "internal")]) == []
    assert state(db, "sess_a") == provenance.Provenance(0, ())


def test_external_source_taints_and_increments_the_version(db):
    assert record(db, "sess_a", [("doc_2", "external")]) == ["doc_2"]
    assert state(db, "sess_a") == provenance.Provenance(1, ("doc_2",))
    assert state(db, "sess_a").tainted


def test_same_source_again_does_not_increment(db):
    record(db, "sess_a", [("doc_2", "external")])
    assert record(db, "sess_a", [("doc_2", "external")]) == []
    assert state(db, "sess_a").version == 1


def test_each_new_external_source_increments_once(db):
    record(db, "sess_a", [("doc_2", "external")])
    new = record(
        db,
        "sess_a",
        [
            ("doc_1", "internal"),
            ("msg_5", "external"),
            ("doc_2", "external"),
            ("msg_6", "external"),
        ],
    )
    assert new == ["msg_5", "msg_6"]
    assert state(db, "sess_a") == provenance.Provenance(3, ("doc_2", "msg_5", "msg_6"))


def test_duplicate_source_within_one_read_counts_once(db):
    assert record(db, "sess_a", [("doc_2", "external"), ("doc_2", "external")]) == ["doc_2"]
    assert state(db, "sess_a").version == 1


def test_taint_is_permanent(db):
    record(db, "sess_a", [("doc_2", "external")])
    record(db, "sess_a", [("doc_1", "internal")])
    record(db, "sess_a", [])
    assert state(db, "sess_a") == provenance.Provenance(1, ("doc_2",))


def test_sessions_are_isolated(db):
    record(db, "sess_a", [("doc_2", "external")])
    assert state(db, "sess_b") == provenance.Provenance(0, ())
    record(db, "sess_b", [("doc_2", "external")])
    assert state(db, "sess_a").version == 1
    assert state(db, "sess_b").version == 1


@pytest.mark.parametrize("label", ["trusted", "", "INTERNAL", "External", None])
def test_unknown_trust_label_is_an_error_and_records_nothing(db, label):
    with pytest.raises(ValueError, match="unknown trust label"):
        record(db, "sess_a", [("doc_2", "external"), ("doc_3", label)])
    assert state(db, "sess_a") == provenance.Provenance(0, ())


def test_unknown_session_is_an_error(db):
    with pytest.raises(LookupError):
        state(db, "sess_missing")


def test_recording_requires_a_transaction(db):
    conn = storage.connect(db)
    try:
        with pytest.raises(RuntimeError):
            provenance.record_sources(conn, "sess_a", [("doc_2", "external")])
    finally:
        conn.close()
    assert state(db, "sess_a").version == 0
