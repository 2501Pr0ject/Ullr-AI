"""LLM relay: the agent's only path to the model (ARCHITECTURE.md section 3).

The agent sits on internal networks with no route to the host or the
internet. This relay is the one container with a route out, and it forwards
exactly one thing: a validated ``POST /api/chat`` to a fixed Ollama upstream.

Contract:
- method and route: ``POST /api/chat`` only;
- the model must be on the configured allow-list;
- strict JSON, bounded size, an allow-list of fields; ``stream`` is forced off;
- the upstream is fixed in the relay's configuration: no destination
  parameter, no generic proxying, no redirect following;
- model management routes are refused explicitly, everything else is absent.

It is not a security control over what the model says. It only bounds what
the agent container can reach.
"""

import json
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from ullr_ai.asgi import error, new_app

MAX_BODY_BYTES = 1_048_576

_REQUEST_FIELDS = frozenset({"model", "messages", "tools", "stream", "options", "think"})
_MESSAGE_FIELDS = frozenset({"role", "content", "thinking", "tool_calls", "tool_name"})
_ROLES = frozenset({"system", "user", "assistant", "tool"})
_OPTION_FIELDS = frozenset({"temperature", "seed", "num_ctx", "num_predict", "top_p", "top_k"})

# Routes of the Ollama API that manage models or reach other functions.
# Refused by name, whatever the method, so that the refusal is explicit.
FORBIDDEN_ROUTES = (
    "/api/pull",
    "/api/push",
    "/api/create",
    "/api/delete",
    "/api/copy",
    "/api/show",
    "/api/generate",
    "/api/embed",
    "/api/embeddings",
    "/api/tags",
    "/api/ps",
    "/api/version",
    "/api/blobs/{digest:path}",
)


class RelayError(ValueError):
    """The request is outside the relay contract."""


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise RelayError("duplicate key")
        obj[key] = value
    return obj


def _no_constant(token: str) -> Any:
    raise RelayError("non-finite number")


def validate_chat_request(raw: bytes, allowed_models: frozenset[str]) -> dict[str, Any]:
    """Return the request to forward, or raise RelayError.

    Only allow-listed fields survive, and ``stream`` is always false in the
    forwarded request.
    """
    try:
        body = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique,
            parse_constant=_no_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise RelayError("invalid JSON") from None
    if type(body) is not dict or not set(body) <= _REQUEST_FIELDS:
        raise RelayError("unknown field")
    if type(body.get("model")) is not str or body["model"] not in allowed_models:
        raise RelayError("model not allowed")

    messages = body.get("messages")
    if type(messages) is not list or not messages:
        raise RelayError("messages required")
    for message in messages:
        if (
            type(message) is not dict
            or not set(message) <= _MESSAGE_FIELDS
            or message.get("role") not in _ROLES
            or type(message.get("content", "")) is not str
        ):
            raise RelayError("invalid message")

    if "tools" in body and type(body["tools"]) is not list:
        raise RelayError("invalid tools")
    if body.get("stream", False) is not False:
        raise RelayError("streaming is not available")
    if "think" in body and type(body["think"]) is not bool:
        raise RelayError("think must be a boolean")
    options = body.get("options", {})
    if type(options) is not dict or not set(options) <= _OPTION_FIELDS:
        raise RelayError("unknown option")
    for value in options.values():
        if type(value) not in (int, float):
            raise RelayError("invalid option value")

    return {**body, "stream": False}


def check_upstream(upstream: httpx.Client, allowed_models: frozenset[str]) -> dict[str, str]:
    """Start-up check: the upstream answers and serves every allowed model.

    Returns ``{model: digest}``. Used by the relay itself only; these upstream
    routes are not exposed to the agent.
    """
    version = upstream.get("/api/version")
    version.raise_for_status()
    tags = upstream.get("/api/tags")
    tags.raise_for_status()
    available = {model["name"]: model["digest"] for model in tags.json()["models"]}
    missing = sorted(allowed_models - set(available))
    if missing:
        raise RuntimeError(f"upstream does not serve the allowed model(s): {missing}")
    return {name: available[name] for name in sorted(allowed_models)}


def create_relay_app(
    upstream: httpx.Client,
    allowed_models: frozenset[str],
    *,
    max_body_bytes: int = MAX_BODY_BYTES,
) -> FastAPI:
    app = new_app(max_body_bytes)

    def forward(request_body: dict[str, Any]) -> Response:
        try:
            reply = upstream.post("/api/chat", json=request_body)
        except httpx.HTTPError:
            return error(502, "upstream_unavailable")
        if reply.status_code != 200:
            return error(502, "upstream_error")
        return Response(reply.content, status_code=200, media_type="application/json")

    @app.post("/api/chat")
    async def chat(request: Request) -> Response:
        try:
            request_body = validate_chat_request(await request.body(), allowed_models)
        except RelayError as exc:
            if str(exc) == "model not allowed":
                return error(403, "model_not_allowed")
            return error(400, "invalid_request")
        return await run_in_threadpool(forward, request_body)

    async def forbidden(request: Request) -> JSONResponse:
        return error(403, "route_forbidden")

    for route in FORBIDDEN_ROUTES:
        app.add_api_route(
            route, forbidden, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]
        )

    return app
