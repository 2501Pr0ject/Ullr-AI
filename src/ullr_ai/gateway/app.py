"""Gateway: sessions, proposals, decisions and the internal execution path.

SECURITY-CRITICAL: manual review required for ``Gateway.propose``,
``Gateway._begin_execution`` and ``Gateway._run_execution``.

Two separate applications, meant for two ports on two networks:
- the agent API, reachable from the agent container;
- the admin API, which creates sessions, reachable only by a trusted party.

There is no transaction spanning the Gateway database and the Tools service.
The execution path records the intent, calls the Tools service with an
idempotency key, then records the outcome (ARCHITECTURE.md section 8).
"""

import hashlib
import re
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from ullr_ai import storage
from ullr_ai.asgi import bearer_token, error, new_app, token_matches
from ullr_ai.gateway import audit, provenance
from ullr_ai.gateway.canon import CANON_VERSION, MAX_BYTES, CanonError, parse_json_strict
from ullr_ai.gateway.db import init_db
from ullr_ai.gateway.executor_client import ExecutorClient, ToolsError
from ullr_ai.gateway.policy import TOOL_TIERS, LoadedPolicy, decide
from ullr_ai.gateway.schemas import Action, SchemaError, parse_execution, parse_proposal

_AGENT_ID = re.compile(r"agent_[0-9]{1,8}")
_ACTION_ID = re.compile(r"act_[0-9a-f]{32}")

# Action state machine (ARCHITECTURE.md section 8). Approval states arrive with M2.
_TRANSITIONS = {
    "PROPOSED": {"DENIED", "ALLOWED", "PENDING_APPROVAL"},
    "ALLOWED": {"EXECUTING"},
    "EXECUTING": {"COMMITTED", "FAILED", "UNKNOWN"},
}

Reply = tuple[int, dict[str, Any]]


@dataclass(frozen=True)
class Session:
    session_id: str
    agent_id: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Gateway:
    def __init__(
        self,
        *,
        db_path: Path | str,
        policy: LoadedPolicy,
        tools: ExecutorClient,
        admin_token: str,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.db_path = str(db_path)
        self.policy = policy.policy
        self.policy_hash = policy.policy_hash
        self.tools = tools
        self.admin_token = admin_token
        self._clock = clock
        init_db(self.db_path)

    # --- helpers -------------------------------------------------------------

    def _now(self) -> str:
        return self._clock().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _audit(self, conn: sqlite3.Connection, event_type: str, **fields: Any) -> None:
        audit.append_event(
            conn, policy_hash=self.policy_hash, event_type=event_type, ts=self._now(), **fields
        )

    def _transition(
        self, conn: sqlite3.Connection, action_id: str, new_status: str, **data: Any
    ) -> None:
        """The only way an action changes state: row update and audit event together."""
        row = conn.execute(
            "SELECT status, session_id, agent_id FROM actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None or new_status not in _TRANSITIONS.get(row["status"], ()):
            raise RuntimeError("illegal action state transition")
        conn.execute("UPDATE actions SET status = ? WHERE action_id = ?", (new_status, action_id))
        self._audit(
            conn,
            new_status,
            action_id=action_id,
            session_id=row["session_id"],
            agent_id=row["agent_id"],
            **data,
        )

    # --- sessions (trusted party only) ---------------------------------------

    def create_session(self, agent_id: str) -> tuple[Session, str]:
        """Create a session and the only token that will ever be bound to it."""
        session = Session("sess_" + secrets.token_hex(16), agent_id)
        token = "ullr_" + secrets.token_urlsafe(32)
        with storage.transaction(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, agent_id, token_hash, created_at)"
                " VALUES (?, ?, ?, ?)",
                (session.session_id, agent_id, _token_hash(token), self._now()),
            )
            self._audit(conn, "SESSION_CREATED", session_id=session.session_id, agent_id=agent_id)
        return session, token

    def authenticate(self, token: str | None) -> Session | None:
        """Map an agent token to its one session and one agent. Never from the payload."""
        if not token:
            return None
        conn = storage.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT session_id, agent_id FROM sessions WHERE token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
        finally:
            conn.close()
        return None if row is None else Session(row["session_id"], row["agent_id"])

    # --- propose -------------------------------------------------------------

    def propose(self, session: Session, raw: bytes) -> Reply:
        try:
            action, reason = parse_proposal(parse_json_strict(raw))
        except (CanonError, SchemaError):
            return 400, {"error": "invalid_request"}

        # Order: validate, decide, and only then look the resource version up.
        # A DENY never contacts the Tools service. Reads need no version, so
        # they are decided and recorded in the single transaction below.
        mutating = TOOL_TIERS[action.tool] != "R0"
        resource_version: int | None = None
        decided_at: int | None = None  # provenance version of the preliminary decision
        if mutating:
            conn = storage.connect(self.db_path)
            try:
                observed = provenance.snapshot(conn, session.session_id)
            finally:
                conn.close()
            if decide(self.policy, action, tainted=observed.tainted).outcome != "DENY":
                decided_at = observed.version
                if action.resource_id is None:
                    resource_version = 0
                else:
                    try:
                        meta = self.tools.resource_meta(action.resource_id)
                    except ToolsError:
                        return 502, {"error": "tools_unavailable"}
                    if meta is None:
                        return 404, {"error": "resource_not_found"}
                    resource_version = meta["version"]

        action_id = "act_" + secrets.token_hex(16)
        execution_id: str | None = None
        with storage.transaction(self.db_path) as conn:
            observed = provenance.snapshot(conn, session.session_id)
            decision = decide(self.policy, action, tainted=observed.tainted)
            if mutating:
                # The decision recorded here must be the one the lookup was based
                # on. If the session's provenance moved in between (a concurrent
                # read), nothing is recorded and the agent must propose again.
                consistent = (
                    decision.outcome == "DENY"
                    if decided_at is None
                    else observed.version == decided_at
                )
                if not consistent:
                    return 409, {"error": "session_changed"}
            conn.execute(
                "INSERT INTO actions (action_id, session_id, agent_id, tool, resource_id,"
                " resource_version, action_hash, policy_hash, canon_version,"
                " provenance_version, reason, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?)",
                (
                    action_id,
                    session.session_id,
                    session.agent_id,
                    action.tool,
                    action.resource_id,
                    resource_version,
                    action.action_hash,
                    self.policy_hash,
                    CANON_VERSION,
                    observed.version,
                    reason,
                    self._now(),
                ),
            )
            self._audit(
                conn,
                "PROPOSED",
                action_id=action_id,
                session_id=session.session_id,
                agent_id=session.agent_id,
                tool=action.tool,
                resource_id=action.resource_id,
                resource_version=resource_version,
                action_hash=action.action_hash,
                canon_version=CANON_VERSION,
                provenance_version=observed.version,
                tainted=observed.tainted,
            )
            if decision.outcome == "DENY":
                self._transition(conn, action_id, "DENIED", reason=decision.reason)
            elif decision.outcome == "REQUIRE_APPROVAL":
                self._transition(conn, action_id, "PENDING_APPROVAL", reason=decision.reason)
            else:
                self._transition(conn, action_id, "ALLOWED", reason=decision.reason)
                execution_id = self._begin_execution(conn, action_id)

        base = {"action_id": action_id, "decision": decision.outcome}
        if decision.outcome == "DENY":
            return 403, {**base, "status": "DENIED", "reason": decision.reason}
        if decision.outcome == "REQUIRE_APPROVAL":
            return 202, {
                **base,
                "status": "PENDING_APPROVAL",
                "reason": decision.reason,
                "action_hash": action.action_hash,
            }
        if execution_id is None:
            raise RuntimeError("allowed action without a recorded intent")
        status, body = self._run_execution(
            session, action_id, execution_id, action, resource_version
        )
        return status, {**base, **body}

    # --- internal execution path ---------------------------------------------

    def _begin_execution(self, conn: sqlite3.Connection, action_id: str) -> str:
        """Record the intent: execution id and EXECUTING, in the caller's transaction."""
        execution_id = "exec_" + secrets.token_hex(16)
        conn.execute(
            "UPDATE actions SET execution_id = ? WHERE action_id = ?", (execution_id, action_id)
        )
        self._transition(conn, action_id, "EXECUTING", execution_id=execution_id)
        return execution_id

    def _run_execution(
        self,
        session: Session,
        action_id: str,
        execution_id: str,
        action: Action,
        resource_version: int | None,
    ) -> Reply:
        """Call the Tools service for an action already in EXECUTING, then record the outcome.

        Shared by allowed actions and, from M2, approved actions.
        """
        mutating = TOOL_TIERS[action.tool] != "R0"
        try:
            outcome = self.tools.execute(
                action.tool,
                action.resource_id,
                action.args,
                idempotency_key=execution_id if mutating else None,
                if_match=resource_version if mutating else None,
            )
        except ToolsError:
            # A mutation may or may not have happened: UNKNOWN until reconciled.
            # A read has no effect to reconcile: FAILED, and no content is returned.
            status = "UNKNOWN" if mutating else "FAILED"
            with storage.transaction(self.db_path) as conn:
                self._transition(conn, action_id, status, error="tools_unavailable")
            return (504 if mutating else 502), {"status": status, "error": "tools_unavailable"}

        if not outcome.executed:
            with storage.transaction(self.db_path) as conn:
                self._transition(conn, action_id, "FAILED", error=outcome.error)
            return 409, {"status": "FAILED", "error": outcome.error}

        with storage.transaction(self.db_path) as conn:
            if not mutating:
                new_sources = provenance.record_sources(
                    conn, session.session_id, list(outcome.sources)
                )
                if new_sources:
                    self._audit(
                        conn,
                        "PROVENANCE_CHANGED",
                        session_id=session.session_id,
                        agent_id=session.agent_id,
                        action_id=action_id,
                        new_sources=new_sources,
                        provenance_version=provenance.snapshot(conn, session.session_id).version,
                    )
            self._transition(conn, action_id, "COMMITTED")
        # Content reaches the agent only after provenance and audit are committed.
        return 200, {"status": "COMMITTED", "result": outcome.result}

    # --- execute (approved actions; approvals arrive with M2) ----------------

    def execute_pending(self, session: Session, action_id: str, raw: bytes) -> Reply:
        """Second call of the approval flow, with the arguments sent again.

        Until signed approvals exist (M2) this never executes anything.
        """
        if _ACTION_ID.fullmatch(action_id) is None:
            return 404, {"error": "not_found"}
        try:
            action = parse_execution(parse_json_strict(raw))
        except (CanonError, SchemaError):
            return 400, {"error": "invalid_request"}
        conn = storage.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT action_hash, status FROM actions WHERE action_id = ? AND session_id = ?",
                (action_id, session.session_id),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return 404, {"error": "not_found"}
        if row["action_hash"] != action.action_hash:
            return 409, {"error": "action_mismatch"}
        if row["status"] == "PENDING_APPROVAL":
            return 403, {"error": "approval_required"}
        return 409, {"error": "not_executable"}


async def _reply(handler: Callable[..., Reply], *args: Any) -> JSONResponse:
    """Run a Gateway operation; any unexpected error is a refusal without detail."""
    try:
        status, body = await run_in_threadpool(handler, *args)
    except Exception:
        return error(500, "internal_error")
    return JSONResponse(body, status_code=status)


def create_agent_app(gateway: Gateway, *, max_body_bytes: int = MAX_BYTES) -> FastAPI:
    """Agent-facing API. It has no route to create, switch or reset a session."""
    app = new_app(max_body_bytes)

    async def session_of(request: Request) -> Session | None:
        try:
            return await run_in_threadpool(gateway.authenticate, bearer_token(request))
        except Exception:
            return None

    @app.post("/v1/actions")
    async def propose(request: Request) -> JSONResponse:
        session = await session_of(request)
        if session is None:
            return error(401, "unauthorized")
        raw = await request.body()
        return await _reply(gateway.propose, session, raw)

    @app.post("/v1/actions/{action_id}/execute")
    async def execute(action_id: str, request: Request) -> JSONResponse:
        session = await session_of(request)
        if session is None:
            return error(401, "unauthorized")
        raw = await request.body()
        return await _reply(gateway.execute_pending, session, action_id, raw)

    return app


def create_admin_app(gateway: Gateway, *, max_body_bytes: int = MAX_BYTES) -> FastAPI:
    """Session issuance, for the benchmark controller or an orchestrator only."""
    app = new_app(max_body_bytes)

    def create(raw: bytes) -> Reply:
        try:
            body = parse_json_strict(raw)
        except CanonError:
            return 400, {"error": "invalid_request"}
        if (
            type(body) is not dict
            or set(body) != {"agent_id"}
            or type(body["agent_id"]) is not str
            or _AGENT_ID.fullmatch(body["agent_id"]) is None
        ):
            return 400, {"error": "invalid_request"}
        session, token = gateway.create_session(body["agent_id"])
        return 201, {
            "session_id": session.session_id,
            "agent_id": session.agent_id,
            "agent_token": token,
        }

    @app.post("/admin/sessions")
    async def create_session(request: Request) -> JSONResponse:
        if not token_matches(bearer_token(request), gateway.admin_token):
            return error(401, "unauthorized")
        raw = await request.body()
        return await _reply(create, raw)

    return app
