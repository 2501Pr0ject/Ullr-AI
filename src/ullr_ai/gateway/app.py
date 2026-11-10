"""Gateway: sessions, proposals, decisions, approvals and the internal execution path.

SECURITY-CRITICAL: manual review required for ``Gateway.propose``,
``Gateway.submit_decision``, ``Gateway.execute_pending``,
``Gateway._begin_execution`` and ``Gateway._run_execution``.

Three separate applications, meant for three ports on three networks:
- the agent API, reachable from the agent container;
- the approver API, where pending requests are listed and signed decisions land;
- the admin API, which creates sessions, reachable only by a trusted party.

There is no transaction spanning the Gateway database and the Tools service.
The execution path records the intent, calls the Tools service with an
idempotency key, then records the outcome (ARCHITECTURE.md section 8).
"""

import hashlib
import json
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
from ullr_ai.gateway import approvals, audit, budget, provenance
from ullr_ai.gateway.canon import (
    CANON_VERSION,
    MAX_BYTES,
    CanonError,
    canonical_json,
    parse_json_strict,
)
from ullr_ai.gateway.db import init_db
from ullr_ai.gateway.executor_client import ExecutorClient, ToolsError
from ullr_ai.gateway.policy import TOOL_TIERS, Decision, LoadedPolicy, decide
from ullr_ai.gateway.reconcile import reconcile
from ullr_ai.gateway.schemas import Action, SchemaError, parse_execution, parse_proposal
from ullr_ai.gateway.signing import TIMESTAMP_FORMAT

_AGENT_ID = re.compile(r"agent_[0-9]{1,8}")
_ACTION_ID = re.compile(r"act_[0-9a-f]{32}")
_SESSION_ID = re.compile(r"sess_[0-9a-f]{32}")

# Action state machine (ARCHITECTURE.md section 8). There is no way back to
# APPROVED: an approval is consumed by EXECUTING and never restored.
_TRANSITIONS = {
    "PROPOSED": {"DENIED", "ALLOWED", "PENDING_APPROVAL"},
    "PENDING_APPROVAL": {"APPROVED", "REJECTED", "EXPIRED", "INVALIDATED"},
    "APPROVED": {"EXECUTING", "EXPIRED", "INVALIDATED"},
    "ALLOWED": {"EXECUTING"},
    "EXECUTING": {"COMMITTED", "FAILED", "UNKNOWN"},
    "UNKNOWN": {"COMMITTED", "FAILED"},
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
        tools: ExecutorClient | None,
        admin_token: str | None,
        approver_token: str | None,
        approvers: dict[str, str],
        clock: Callable[[], datetime] = _utc_now,
        recover_on_start: bool = True,
    ) -> None:
        self.db_path = str(db_path)
        self.policy = policy.policy
        self.policy_hash = policy.policy_hash
        self.tools = tools
        self.admin_token = admin_token
        self.approver_token = approver_token
        self.approvers = approvals.validate_registry(approvers)
        self._clock = clock
        init_db(self.db_path)
        # Only the process that can reach the Tools service recovers and reconciles.
        if recover_on_start:
            self.recover()

    # --- helpers -------------------------------------------------------------

    def _tools(self) -> ExecutorClient:
        if self.tools is None:
            raise RuntimeError("this Gateway process has no access to the Tools service")
        return self.tools

    def _now(self) -> str:
        return self._clock().strftime(TIMESTAMP_FORMAT)

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

    def _decide(
        self, conn: sqlite3.Connection, session: Session, action: Action
    ) -> tuple[provenance.Provenance, Decision]:
        """Policy decision plus the limit on pending approvals (T16)."""
        observed = provenance.snapshot(conn, session.session_id)
        decision = decide(self.policy, action, tainted=observed.tainted)
        if decision.outcome == "REQUIRE_APPROVAL":
            pending = conn.execute(
                "SELECT COUNT(*) AS n FROM actions JOIN approvals USING (action_id)"
                " WHERE session_id = ? AND status = 'PENDING_APPROVAL' AND expires_at > ?",
                (session.session_id, self._now()),
            ).fetchone()["n"]
            if pending >= self.policy.approval.max_pending_per_session:
                decision = Decision("DENY", "too_many_pending")
        return observed, decision

    def _stale(self, conn: sqlite3.Connection, record: dict[str, Any]) -> tuple[str, str] | None:
        """Why an approval can no longer be used, as ``(new status, reason)``, or None."""
        if self._now() >= record["expires_at"]:
            return "EXPIRED", "expired"
        if record["policy_hash"] != self.policy_hash:
            return "INVALIDATED", "policy_changed"
        if record["canon_version"] != CANON_VERSION:
            return "INVALIDATED", "canon_changed"
        current = provenance.snapshot(conn, record["session_id"]).version
        if current != record["provenance_version"]:
            return "INVALIDATED", "provenance_changed"
        return None

    def _expire_overdue(self, conn: sqlite3.Connection) -> None:
        overdue = conn.execute(
            "SELECT action_id FROM actions JOIN approvals USING (action_id)"
            " WHERE status IN ('PENDING_APPROVAL', 'APPROVED') AND expires_at <= ?",
            (self._now(),),
        ).fetchall()
        for row in overdue:
            self._transition(conn, row["action_id"], "EXPIRED", reason="expired")

    # --- start-up ------------------------------------------------------------

    def recover(self) -> dict[str, int]:
        """Run at start-up: no execution is in flight.

        Approvals issued under another policy or canon version are invalidated,
        overdue ones expire, and every open execution is reconciled.
        """
        with storage.transaction(self.db_path) as conn:
            outdated = conn.execute(
                "SELECT action_id, policy_hash FROM actions"
                " WHERE status IN ('PENDING_APPROVAL', 'APPROVED')"
                " AND (policy_hash != ? OR canon_version != ?)",
                (self.policy_hash, CANON_VERSION),
            ).fetchall()
            for row in outdated:
                reason = (
                    "policy_changed" if row["policy_hash"] != self.policy_hash else "canon_changed"
                )
                self._transition(conn, row["action_id"], "INVALIDATED", reason=reason)
            self._expire_overdue(conn)
        return reconcile(self, include_executing=True)

    def reconcile_unknown(self) -> dict[str, int]:
        """Resolve ``UNKNOWN`` executions while the Gateway is running.

        Never touches ``EXECUTING``: such an action may be a live request.
        """
        return reconcile(self, include_executing=False)

    def state(self) -> Reply:
        """Read-only view for the controller: actions, reservations, audit check."""
        conn = storage.connect(self.db_path)
        try:
            actions = [
                dict(row)
                for row in conn.execute(
                    "SELECT action_id, session_id, agent_id, tool, resource_id, status,"
                    " execution_id, created_at FROM actions ORDER BY created_at"
                )
            ]
            reservations = [
                dict(row)
                for row in conn.execute(
                    "SELECT action_id, budget_key, amount_cents, state, created_at"
                    " FROM budget_reservations ORDER BY id"
                )
            ]
            report = audit.verify_chain(conn)
        finally:
            conn.close()
        return 200, {
            "actions": actions,
            "reservations": reservations,
            "audit": {"ok": report.ok, "events": report.events},
        }

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
                "SELECT session_id, agent_id FROM sessions"
                " WHERE token_hash = ? AND revoked_at IS NULL",
                (_token_hash(token),),
            ).fetchone()
        finally:
            conn.close()
        return None if row is None else Session(row["session_id"], row["agent_id"])

    def _active(self, conn: sqlite3.Connection, session: Session) -> bool:
        """Whether the session is still valid, read inside the caller's transaction.

        Authentication happened earlier in the request. A revocation committed
        since then must win: this check runs in the same ``BEGIN IMMEDIATE``
        transaction that would record or consume anything.
        """
        row = conn.execute(
            "SELECT revoked_at FROM sessions WHERE session_id = ?", (session.session_id,)
        ).fetchone()
        return row is not None and row["revoked_at"] is None

    def revoke_session(self, session_id: str) -> Reply:
        """End a session: its token stops working and its open approvals are invalidated."""
        if _SESSION_ID.fullmatch(session_id) is None:
            return 404, {"error": "not_found"}
        with storage.transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT agent_id, revoked_at FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if row is None:
                return 404, {"error": "not_found"}
            if row["revoked_at"] is None:
                conn.execute(
                    "UPDATE sessions SET revoked_at = ? WHERE session_id = ?",
                    (self._now(), session_id),
                )
                self._audit(
                    conn, "SESSION_REVOKED", session_id=session_id, agent_id=row["agent_id"]
                )
                open_approvals = conn.execute(
                    "SELECT action_id FROM actions WHERE session_id = ?"
                    " AND status IN ('PENDING_APPROVAL', 'APPROVED')",
                    (session_id,),
                ).fetchall()
                for action in open_approvals:
                    self._transition(
                        conn, action["action_id"], "INVALIDATED", reason="session_revoked"
                    )
        return 200, {"session_id": session_id, "revoked": True}

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
                if not self._active(conn, session):
                    return 401, {"error": "unauthorized"}
                observed, preliminary = self._decide(conn, session, action)
            finally:
                conn.close()
            if preliminary.outcome != "DENY":
                decided_at = observed.version
                if action.resource_id is None:
                    resource_version = 0
                else:
                    try:
                        meta = self._tools().resource_meta(action.resource_id)
                    except ToolsError:
                        return 502, {"error": "tools_unavailable"}
                    if meta is None:
                        return 404, {"error": "resource_not_found"}
                    resource_version = meta["version"]

        action_id = "act_" + secrets.token_hex(16)
        execution_id: str | None = None
        expires_at: str | None = None
        with storage.transaction(self.db_path) as conn:
            if not self._active(conn, session):
                # Revoked since authentication: nothing is recorded or executed.
                return 401, {"error": "unauthorized"}
            observed, decision = self._decide(conn, session, action)
            if mutating:
                # The decision recorded here must be the one the lookup was based
                # on. If the session moved in between (a concurrent read tainted
                # it, or the pending limit was reached), nothing is recorded and
                # the agent must propose again.
                if decided_at is None:
                    consistent = decision.outcome == "DENY"
                else:
                    consistent = observed.version == decided_at and decision.outcome != "DENY"
                if not consistent:
                    return 409, {"error": "session_changed"}
            conn.execute(
                "INSERT INTO actions (action_id, session_id, agent_id, tool, resource_id,"
                " resource_version, args, action_hash, policy_hash, canon_version,"
                " provenance_version, reason, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PROPOSED', ?)",
                (
                    action_id,
                    session.session_id,
                    session.agent_id,
                    action.tool,
                    action.resource_id,
                    # A read is bound to no resource version: recorded as 0.
                    0 if resource_version is None else resource_version,
                    canonical_json(action.args).decode("utf-8"),
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
                expires_at = approvals.create(
                    conn, action_id, self._clock(), self.policy.approval.ttl_seconds
                )
                self._transition(
                    conn,
                    action_id,
                    "PENDING_APPROVAL",
                    reason=decision.reason,
                    expires_at=expires_at,
                )
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
                "expires_at": expires_at,
            }
        if execution_id is None:
            raise RuntimeError("allowed action without a recorded intent")
        status, body = self._run_execution(
            session, action_id, execution_id, action, resource_version
        )
        return status, {**base, **body}

    # --- approvals -----------------------------------------------------------

    def pending_requests(self) -> Reply:
        """Approval requests awaiting a decision, with Gateway-derived provenance."""
        with storage.transaction(self.db_path) as conn:
            self._expire_overdue(conn)
            pending = conn.execute(
                "SELECT action_id FROM actions WHERE status = 'PENDING_APPROVAL'"
                " ORDER BY created_at"
            ).fetchall()
            views = []
            for row in pending:
                record = approvals.record_of(conn, row["action_id"])
                if record is not None:
                    views.append(approvals.request_view(conn, record))
        return 200, {"pending": views}

    def submit_decision(self, action_id: str, raw: bytes) -> Reply:
        """Accept a signed decision on a pending approval, or change nothing."""
        if _ACTION_ID.fullmatch(action_id) is None:
            return 404, {"error": "not_found"}
        try:
            body = parse_json_strict(raw)
        except CanonError:
            return 400, {"error": "invalid_request"}
        if type(body) is not dict or set(body) != {"payload", "signature"}:
            return 400, {"error": "invalid_request"}

        with storage.transaction(self.db_path) as conn:
            record = approvals.record_of(conn, action_id)
            if record is None:
                return 404, {"error": "not_found"}
            if record["status"] != "PENDING_APPROVAL":
                return 409, {"error": "not_pending"}
            stale = self._stale(conn, record)
            if stale is not None:
                self._transition(conn, action_id, stale[0], reason=stale[1])
                return 409, {"error": "approval_" + stale[0].lower(), "reason": stale[1]}
            try:
                payload = approvals.check_decision(
                    record, body["payload"], body["signature"], self.approvers
                )
            except approvals.DecisionError:
                # A bad decision changes nothing: it cannot kill a pending approval.
                return 403, {"error": "invalid_decision"}
            if self._now() >= payload.expires_at:
                return 403, {"error": "invalid_decision"}
            conn.execute(
                "UPDATE approvals SET approver_id = ?, decision = ?, signature = ?, payload = ?,"
                " decided_at = ? WHERE action_id = ?",
                (
                    payload.approver_id,
                    payload.decision,
                    body["signature"],
                    canonical_json(payload.model_dump()).decode("utf-8"),
                    self._now(),
                    action_id,
                ),
            )
            new_status = "APPROVED" if payload.decision == "APPROVE" else "REJECTED"
            self._transition(conn, action_id, new_status, approver_id=payload.approver_id)
        return 200, {"action_id": action_id, "status": new_status}

    # --- execute (approved actions) ------------------------------------------

    def execute_pending(self, session: Session, action_id: str, raw: bytes) -> Reply:
        """Execute an approved action, with the arguments sent again.

        One ``BEGIN IMMEDIATE`` transaction verifies status, expiry, signature,
        action hash, policy hash, canon version and provenance version, reserves
        every applicable budget, consumes the approval and records the intent.
        If any check fails, nothing is consumed and nothing is executed.
        """
        if _ACTION_ID.fullmatch(action_id) is None:
            return 404, {"error": "not_found"}
        try:
            action = parse_execution(parse_json_strict(raw))
        except (CanonError, SchemaError):
            return 400, {"error": "invalid_request"}

        with storage.transaction(self.db_path) as conn:
            if not self._active(conn, session):
                # Revoked since authentication: the approval is not consumed.
                return 401, {"error": "unauthorized"}
            owned = conn.execute(
                "SELECT action_hash FROM actions WHERE action_id = ? AND session_id = ?",
                (action_id, session.session_id),
            ).fetchone()
            if owned is None:
                return 404, {"error": "not_found"}
            if owned["action_hash"] != action.action_hash:
                return 409, {"error": "action_mismatch"}
            record = approvals.record_of(conn, action_id)
            if record is None:
                # Allowed and denied actions are never executable through this route.
                return 409, {"error": "not_executable"}
            if record["status"] == "PENDING_APPROVAL":
                return 403, {"error": "approval_required"}
            if record["status"] != "APPROVED":
                return 409, {"error": "not_executable"}

            stale = self._stale(conn, record)
            if stale is None:
                try:
                    payload = approvals.check_decision(
                        record, json.loads(record["payload"]), record["signature"], self.approvers
                    )
                    if payload.decision != "APPROVE":
                        raise approvals.DecisionError
                except (approvals.DecisionError, TypeError, ValueError):
                    stale = ("INVALIDATED", "decision_no_longer_valid")
                else:
                    if self._now() >= payload.expires_at:
                        stale = ("EXPIRED", "expired")
            if stale is not None:
                self._transition(conn, action_id, stale[0], reason=stale[1])
                return 409, {"error": "approval_" + stale[0].lower(), "reason": stale[1]}

            tool_policy = self.policy.tools.get(action.tool)
            if tool_policy is None:
                self._transition(conn, action_id, "INVALIDATED", reason="policy_changed")
                return 409, {"error": "approval_invalidated", "reason": "policy_changed"}
            if tool_policy.budgets:
                exceeded = budget.reserve(
                    conn,
                    action_id=action_id,
                    budgets=tool_policy.budgets,
                    account_id=action.resource_id,
                    agent_id=session.agent_id,
                    amount=action.args["amount"],
                    now=self._clock(),
                )
                if exceeded is not None:
                    # Nothing was written: the approval is not consumed.
                    return 409, {"error": "budget_exceeded", "budget": exceeded}
            execution_id = self._begin_execution(conn, action_id)

        status, body = self._run_execution(
            session, action_id, execution_id, action, record["resource_version"]
        )
        return status, {"action_id": action_id, **body}

    # --- internal execution path ---------------------------------------------

    def _begin_execution(self, conn: sqlite3.Connection, action_id: str) -> str:
        """Record the intent: execution id and EXECUTING, in the caller's transaction.

        For an approved action this is the consumption of the approval.
        """
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

        Shared by allowed actions and approved actions.
        """
        mutating = TOOL_TIERS[action.tool] != "R0"
        try:
            outcome = self._tools().execute(
                action.tool,
                action.resource_id,
                action.args,
                idempotency_key=execution_id if mutating else None,
                if_match=resource_version if mutating else None,
            )
        except ToolsError:
            # A mutation may or may not have happened: UNKNOWN until reconciled,
            # and the budget stays held. A read has no effect to reconcile:
            # FAILED, and no content is returned.
            status = "UNKNOWN" if mutating else "FAILED"
            with storage.transaction(self.db_path) as conn:
                self._transition(conn, action_id, status, error="tools_unavailable")
                budget.settle(conn, action_id, "HELD" if mutating else "RELEASED")
            return (504 if mutating else 502), {"status": status, "error": "tools_unavailable"}

        if not outcome.executed:
            with storage.transaction(self.db_path) as conn:
                self._transition(conn, action_id, "FAILED", error=outcome.error)
                budget.settle(conn, action_id, "RELEASED")
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
            budget.settle(conn, action_id, "COMMITTED")
        # Content reaches the agent only after provenance and audit are committed.
        return 200, {"status": "COMMITTED", "result": outcome.result}


async def _reply(handler: Callable[..., Reply], *args: Any) -> JSONResponse:
    """Run a Gateway operation; any unexpected error is a refusal without detail."""
    try:
        status, body = await run_in_threadpool(handler, *args)
    except Exception:
        return error(500, "internal_error")
    return JSONResponse(body, status_code=status)


def create_agent_app(gateway: Gateway, *, max_body_bytes: int = MAX_BYTES) -> FastAPI:
    """Agent-facing API. It has no route to create, switch or reset a session,
    and none to list approvals or submit a decision."""
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


def create_approver_app(gateway: Gateway, *, max_body_bytes: int = MAX_BYTES) -> FastAPI:
    """Approver channel. Listing needs the approver-channel token; a decision is
    authenticated by its signature alone."""
    app = new_app(max_body_bytes)

    @app.get("/v1/approvals")
    async def pending(request: Request) -> JSONResponse:
        if not token_matches(bearer_token(request), gateway.approver_token):
            return error(401, "unauthorized")
        return await _reply(gateway.pending_requests)

    @app.post("/v1/approvals/{action_id}/decision")
    async def decision(action_id: str, request: Request) -> JSONResponse:
        raw = await request.body()
        return await _reply(gateway.submit_decision, action_id, raw)

    return app


def create_admin_app(gateway: Gateway, *, max_body_bytes: int = MAX_BYTES) -> FastAPI:
    """Session issuance and revocation, and a read-only view of the Gateway state,
    for the benchmark controller or an orchestrator only. This application
    needs no access to the Tools service."""
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

    @app.post("/admin/sessions/{session_id}/revoke")
    async def revoke_session(session_id: str, request: Request) -> JSONResponse:
        if not token_matches(bearer_token(request), gateway.admin_token):
            return error(401, "unauthorized")
        return await _reply(gateway.revoke_session, session_id)

    @app.get("/admin/state")
    async def state(request: Request) -> JSONResponse:
        if not token_matches(bearer_token(request), gateway.admin_token):
            return error(401, "unauthorized")
        return await _reply(gateway.state)

    return app
