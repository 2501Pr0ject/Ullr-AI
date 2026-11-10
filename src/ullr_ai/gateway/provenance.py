"""Session provenance, derived only from reads the Gateway proxied (ARCHITECTURE.md section 6).

The only inputs are the trust labels returned by the Tools service. Nothing
an agent sends can add, remove or relabel a source, and there is no operation
that clears a session: taint is permanent for the life of the session.
"""

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class Provenance:
    version: int
    sources: tuple[str, ...]

    @property
    def tainted(self) -> bool:
        return len(self.sources) > 0


def snapshot(conn: sqlite3.Connection, session_id: str) -> Provenance:
    row = conn.execute(
        "SELECT provenance_version FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()
    if row is None:
        raise LookupError("unknown session")
    sources = conn.execute(
        "SELECT source_id FROM session_sources WHERE session_id = ? ORDER BY source_id",
        (session_id,),
    ).fetchall()
    return Provenance(row["provenance_version"], tuple(source["source_id"] for source in sources))


def record_sources(
    conn: sqlite3.Connection, session_id: str, sources: list[tuple[str, str]]
) -> list[str]:
    """Record the ``(source_id, trust_label)`` pairs observed by one read.

    Returns the external sources that are new to the session. The provenance
    version increments once for each of them. Must run inside a transaction.
    """
    if not conn.in_transaction:
        raise RuntimeError("provenance must be recorded inside a transaction")
    new_sources: list[str] = []
    for source_id, trust_label in sources:
        if trust_label == "internal":
            continue
        if trust_label != "external":
            raise ValueError("unknown trust label")
        known = conn.execute(
            "SELECT 1 FROM session_sources WHERE session_id = ? AND source_id = ?",
            (session_id, source_id),
        ).fetchone()
        if known is None and source_id not in new_sources:
            conn.execute(
                "INSERT INTO session_sources (session_id, source_id) VALUES (?, ?)",
                (session_id, source_id),
            )
            new_sources.append(source_id)
    if new_sources:
        conn.execute(
            "UPDATE sessions SET provenance_version = provenance_version + ? WHERE session_id = ?",
            (len(new_sources), session_id),
        )
    return new_sources
