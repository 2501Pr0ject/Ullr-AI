"""SQLite helpers shared by the Gateway and the Tools service.

Every connection uses WAL journaling, so that several processes (the three
Gateway containers, the two Tools containers) can share one database file,
and ``synchronous=FULL``, so that a committed transaction, in particular a
recorded execution intent, survives an operating-system crash. Both settings
are verified on every connection: a database that cannot honour them is not used.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SYNCHRONOUS_FULL = 2


class StorageError(RuntimeError):
    """The database cannot provide the required durability or locking mode."""


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection in autocommit mode: transactions are always explicit."""
    conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        conn.execute("PRAGMA synchronous=FULL")
        synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
        conn.execute("PRAGMA foreign_keys=ON")
        if str(journal_mode).lower() != "wal" or synchronous != _SYNCHRONOUS_FULL:
            raise StorageError("database is not in WAL mode with synchronous=FULL")
    except BaseException:
        conn.close()
        raise
    return conn


@contextmanager
def transaction(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """One ``BEGIN IMMEDIATE`` transaction: commit on success, roll back on any error."""
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
