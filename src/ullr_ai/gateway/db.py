"""Gateway SQLite schema.

Triggers make the security-relevant history append-only at the database
level: audit events cannot be updated or deleted, a session cannot be removed
or re-bound, and its provenance can only grow.
"""

from pathlib import Path

from ullr_ai import storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    provenance_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session_sources (
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    source_id TEXT NOT NULL,
    PRIMARY KEY (session_id, source_id)
);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions (session_id),
    agent_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    resource_id TEXT,
    resource_version INTEGER,
    action_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    canon_version INTEGER NOT NULL,
    provenance_version INTEGER NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    execution_id TEXT UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    event TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

-- INSERT OR REPLACE removes the conflicting row without firing DELETE triggers.
-- These BEFORE INSERT triggers run first and close that path.
CREATE TRIGGER IF NOT EXISTS audit_events_insert_at_tail_only
BEFORE INSERT ON audit_events
WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events)
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS sessions_no_replace
BEFORE INSERT ON sessions
WHEN EXISTS (
    SELECT 1 FROM sessions
    WHERE session_id = NEW.session_id OR token_hash = NEW.token_hash
)
BEGIN
    SELECT RAISE(ABORT, 'sessions cannot be replaced');
END;

CREATE TRIGGER IF NOT EXISTS sessions_no_delete
BEFORE DELETE ON sessions
BEGIN
    SELECT RAISE(ABORT, 'sessions cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS sessions_identity_is_fixed
BEFORE UPDATE ON sessions
WHEN NEW.session_id IS NOT OLD.session_id
  OR NEW.agent_id IS NOT OLD.agent_id
  OR NEW.token_hash IS NOT OLD.token_hash
BEGIN
    SELECT RAISE(ABORT, 'session identity is fixed');
END;

CREATE TRIGGER IF NOT EXISTS sessions_provenance_only_grows
BEFORE UPDATE ON sessions
WHEN NEW.provenance_version < OLD.provenance_version
BEGIN
    SELECT RAISE(ABORT, 'provenance version cannot decrease');
END;

CREATE TRIGGER IF NOT EXISTS session_sources_no_update
BEFORE UPDATE ON session_sources
BEGIN
    SELECT RAISE(ABORT, 'session_sources is append-only');
END;

CREATE TRIGGER IF NOT EXISTS session_sources_no_delete
BEFORE DELETE ON session_sources
BEGIN
    SELECT RAISE(ABORT, 'session_sources is append-only');
END;
"""


def init_db(db_path: Path | str) -> None:
    conn = storage.connect(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
