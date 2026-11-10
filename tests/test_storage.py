"""SQLite settings and multi-process access (WAL, synchronous=FULL)."""

import subprocess
import sys

import pytest

from ullr_ai import storage
from ullr_ai.gateway import audit
from ullr_ai.gateway.db import init_db

# Run in separate OS processes: each appends audit events to the same file.
WRITER = """
import sys
from ullr_ai import storage
from ullr_ai.gateway import audit

db, name, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
for index in range(count):
    with storage.transaction(db) as conn:
        audit.append_event(
            conn,
            policy_hash="sha256:" + "0" * 64,
            event_type="TEST",
            ts="2026-11-11T10:00:00.000000Z",
            writer=name,
            index=index,
        )
"""


def test_every_connection_is_wal_and_synchronous_full(tmp_path):
    path = tmp_path / "db.sqlite"
    for _ in range(2):
        conn = storage.connect(path)
        try:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        finally:
            conn.close()


def test_database_that_cannot_use_wal_is_refused():
    with pytest.raises(storage.StorageError):
        storage.connect(":memory:")


def test_transaction_rolls_back_on_error(tmp_path):
    path = tmp_path / "db.sqlite"
    with storage.transaction(path) as conn:
        conn.execute("CREATE TABLE t (x)")
    with pytest.raises(ZeroDivisionError), storage.transaction(path) as conn:
        conn.execute("INSERT INTO t VALUES (1)")
        raise ZeroDivisionError
    with storage.transaction(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0


def test_separate_processes_share_one_database_without_losing_writes(tmp_path):
    """Six OS processes append to the audit chain concurrently.

    The chain only stays contiguous and verifiable if BEGIN IMMEDIATE really
    serializes writers across processes.
    """
    path = tmp_path / "gateway.db"
    init_db(path)
    writers, events_each = 6, 25
    processes = [
        subprocess.Popen(  # noqa: S603 (fixed interpreter and script)
            [sys.executable, "-c", WRITER, str(path), f"w{n}", str(events_each)]
        )
        for n in range(writers)
    ]
    assert [process.wait(timeout=120) for process in processes] == [0] * writers

    conn = storage.connect(path)
    try:
        report = audit.verify_chain(conn)
        per_writer = dict(
            conn.execute(
                "SELECT json_extract(event, '$.writer'), COUNT(*) FROM audit_events GROUP BY 1"
            ).fetchall()
        )
    finally:
        conn.close()
    assert report == audit.AuditReport(True, writers * events_each)
    assert per_writer == {f"w{n}": events_each for n in range(writers)}
