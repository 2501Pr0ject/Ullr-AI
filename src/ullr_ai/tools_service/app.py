"""Tools service HTTP APIs.

Two separate applications, meant for two ports on two networks:
- the executor API, used by the Gateway only, with the executor token;
- the admin API, used by the benchmark controller only, with the admin token.
Neither exposes the other's routes or accepts the other's token.
"""

import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ullr_ai.asgi import bearer_token, error, new_app, token_matches
from ullr_ai.gateway.canon import MAX_BYTES, CanonError, parse_json_strict
from ullr_ai.gateway.schemas import SchemaError, validate_action
from ullr_ai.tools_service.executions import MUTATING_TOOLS, execute_mutation
from ullr_ai.tools_service.state import Seed, ToolsState

_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9_-]{8,64}")
_IF_MATCH = re.compile(r"0|[1-9][0-9]{0,15}")
_RESOURCE_ID = re.compile(r"(doc|acct|cfg)_[0-9]{1,8}")


def _not_executed(status: int, code: str) -> JSONResponse:
    return JSONResponse({"executed": False, "error": code}, status_code=status)


def create_executor_app(
    state: ToolsState, executor_token: str, *, max_body_bytes: int = MAX_BYTES
) -> FastAPI:
    app = new_app(max_body_bytes)

    def authorized(request: Request) -> bool:
        return token_matches(bearer_token(request), executor_token)

    @app.post("/v1/execute")
    async def execute(request: Request) -> JSONResponse:
        if not authorized(request):
            return _not_executed(401, "unauthorized")
        raw = await request.body()
        status, body = await run_in_threadpool(
            _execute,
            state,
            raw,
            request.headers.get("idempotency-key"),
            request.headers.get("if-match"),
        )
        return JSONResponse(body, status_code=status)

    @app.get("/v1/resources/{resource_id}")
    def resource(resource_id: str, request: Request) -> JSONResponse:
        if not authorized(request):
            return error(401, "unauthorized")
        if _RESOURCE_ID.fullmatch(resource_id) is None:
            return error(404, "not_found")
        meta = state.resource_meta(resource_id)
        if meta is None:
            return error(404, "not_found")
        return JSONResponse(meta)

    @app.get("/v1/executions/{idempotency_key}")
    def execution(idempotency_key: str, request: Request) -> JSONResponse:
        if not authorized(request):
            return error(401, "unauthorized")
        if _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
            return error(404, "not_found")
        record = state.execution(idempotency_key)
        if record is None:
            return error(404, "not_found")
        return JSONResponse(record)

    return app


def _execute(
    state: ToolsState, raw: bytes, idempotency_key: str | None, if_match: str | None
) -> tuple[int, dict[str, Any]]:
    try:
        request = parse_json_strict(raw)
        if type(request) is not dict or set(request) != {"tool", "resource_id", "args"}:
            raise SchemaError("invalid request")
        action = validate_action(request["tool"], request["resource_id"], request["args"])
    except (CanonError, SchemaError):
        return 422, {"executed": False, "error": "invalid_request"}

    if action.tool not in MUTATING_TOOLS:
        found = state.read(action.tool, action.resource_id)
        if found is None:
            return 404, {"executed": False, "error": "not_found"}
        return 200, {"executed": True, **found}

    if idempotency_key is None or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        return 400, {"executed": False, "error": "idempotency_key_required"}
    if if_match is None or _IF_MATCH.fullmatch(if_match) is None:
        return 428, {"executed": False, "error": "precondition_required"}
    return execute_mutation(state, action, idempotency_key, int(if_match))


def create_admin_app(
    state: ToolsState, admin_token: str, default_seed: Seed, *, max_body_bytes: int = MAX_BYTES
) -> FastAPI:
    app = new_app(max_body_bytes)

    def authorized(request: Request) -> bool:
        return token_matches(bearer_token(request), admin_token)

    @app.post("/admin/reset")
    async def reset(request: Request) -> JSONResponse:
        if not authorized(request):
            return error(401, "unauthorized")
        raw = await request.body()
        seed = default_seed
        if raw:
            try:
                body = parse_json_strict(raw)
                if type(body) is not dict or set(body) != {"seed"}:
                    raise CanonError("invalid request")
                seed = Seed.model_validate(body["seed"])
            except (CanonError, ValidationError):
                return error(400, "invalid_request")
        await run_in_threadpool(state.reset, seed)
        return JSONResponse({"reset": True})

    @app.get("/admin/snapshot")
    def snapshot(request: Request) -> JSONResponse:
        if not authorized(request):
            return error(401, "unauthorized")
        return JSONResponse(state.snapshot())

    @app.get("/admin/executions")
    def executions(request: Request) -> JSONResponse:
        if not authorized(request):
            return error(401, "unauthorized")
        return JSONResponse({"executions": state.executions()})

    return app
