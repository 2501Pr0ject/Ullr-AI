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


# --- start-up initialization by several processes ------------------------------

# Each process waits for the same instant, then initializes the database the
# way its service does at start-up.
STARTER = """
import sys, time
from ullr_ai import serve
from ullr_ai.gateway.db import init_db
from ullr_ai.tools_service.state import ToolsState

db, kind, start = sys.argv[1], sys.argv[2], float(sys.argv[3])
while time.time() < start:
    pass
serve._check_database(db)
ToolsState(db) if kind == "tools" else init_db(db)
print("ok")
"""


@pytest.mark.parametrize("kind", ["tools", "gateway"])
def test_processes_starting_together_on_a_new_database_all_initialize(tmp_path, kind):
    import time

    for round_ in range(5):
        db = tmp_path / f"{kind}-{round_}.db"
        start = str(time.time() + 1.5)
        processes = [
            subprocess.Popen(  # noqa: S603
                [sys.executable, "-c", STARTER, str(db), kind, start],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(3)
        ]
        results = [process.communicate(timeout=60) for process in processes]
        for (out, err), process in zip(results, processes, strict=True):
            assert process.returncode == 0, err
            assert out.strip() == "ok"
        conn = storage.connect(db)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        finally:
            conn.close()
        assert ("executions" if kind == "tools" else "audit_events") in tables


def test_initialization_is_idempotent(tmp_path):
    from ullr_ai.tools_service.state import ToolsState

    db = tmp_path / "db.sqlite"
    for _ in range(3):
        init_db(db)
        ToolsState(db)


def test_only_a_locked_database_is_retried_and_only_a_bounded_number_of_times(monkeypatch):
    import sqlite3

    calls, sleeps = [], []

    def locked(path):
        calls.append(path)
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(storage, "connect", locked)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        storage.initialize("x.db", attempts=4, delay=0.5, sleep=sleeps.append)
    assert len(calls) == 4
    assert sleeps == [0.5, 0.5, 0.5]


@pytest.mark.parametrize(
    "error",
    [
        __import__("sqlite3").OperationalError("unable to open database file"),
        __import__("sqlite3").OperationalError("disk I/O error"),
        __import__("sqlite3").DatabaseError("file is not a database"),
        storage.StorageError("database is not in WAL mode with synchronous=FULL"),
    ],
)
def test_any_other_initialization_error_fails_at_once(monkeypatch, error):
    calls = []

    def failing(path):
        calls.append(path)
        raise error

    monkeypatch.setattr(storage, "connect", failing)
    with pytest.raises(type(error)):
        storage.initialize("x.db", sleep=lambda _: pytest.fail("must not wait"))
    assert len(calls) == 1


def test_a_lock_that_clears_is_waited_out(monkeypatch, tmp_path):
    import sqlite3

    real, failures = storage.connect, [2]

    def flaky(path):
        if failures[0]:
            failures[0] -= 1
            raise sqlite3.OperationalError("database is locked")
        return real(path)

    monkeypatch.setattr(storage, "connect", flaky)
    db = tmp_path / "db.sqlite"
    storage.initialize(db, "CREATE TABLE IF NOT EXISTS t (x)", sleep=lambda _: None)
    assert failures == [0]


def test_a_schema_error_is_not_retried(tmp_path):
    import sqlite3

    with pytest.raises(sqlite3.OperationalError, match="syntax error"):
        storage.initialize(tmp_path / "db.sqlite", "CREATE TABLE (", sleep=lambda _: None)
