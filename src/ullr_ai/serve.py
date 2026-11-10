"""Process entry point: one role, one application, one port.

    ULLR_ROLE=gateway-api python -m ullr_ai.serve

Each container runs exactly one role and is given only the secrets of that
role, as files in ``ULLR_SECRETS_DIR``. Secrets are never read from the
environment. A role that needs a secret it was not given refuses to start.
"""

import json
import os
import sqlite3
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from ullr_ai import storage
from ullr_ai.gateway import approvals
from ullr_ai.gateway.app import (
    Gateway,
    create_admin_app,
    create_agent_app,
    create_approver_app,
)
from ullr_ai.gateway.executor_client import ExecutorClient
from ullr_ai.gateway.policy import load_policy
from ullr_ai.gateway.reconcile import start_loop
from ullr_ai.llm_relay import check_upstream, create_relay_app
from ullr_ai.tools_service import app as tools_app
from ullr_ai.tools_service.state import Seed, ToolsState

ROLES = (
    "gateway-api",
    "gateway-admin",
    "gateway-approver",
    "tools-executor",
    "tools-admin",
    "llm-relay",
)
MIN_SECRET_LENGTH = 32


class ConfigError(RuntimeError):
    """The process is not configured for its role."""


def read_secret(env: Mapping[str, str], name: str) -> str:
    path = Path(env.get("ULLR_SECRETS_DIR", "/run/secrets")) / name
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise ConfigError(f"secret {name} is not available to this role") from None
    if len(value) < MIN_SECRET_LENGTH:
        raise ConfigError(f"secret {name} is too short")
    return value


def _require(env: Mapping[str, str], name: str) -> str:
    try:
        return env[name]
    except KeyError:
        raise ConfigError(f"{name} is not set") from None


def _check_database(path: str) -> None:
    """Fail at start-up, not at the first request, if WAL or FULL sync is unavailable."""
    storage.connect(path).close()


def _gateway(env: Mapping[str, str], **kwargs: Any) -> Gateway:
    db_path = _require(env, "ULLR_GATEWAY_DB")
    _check_database(db_path)
    return Gateway(db_path=db_path, policy=load_policy(_require(env, "ULLR_POLICY")), **kwargs)


def build_app(env: Mapping[str, str]) -> Any:
    """Build the single ASGI application of this process's role."""
    role = env.get("ULLR_ROLE")
    if role == "gateway-api":
        tools = ExecutorClient(
            httpx.Client(base_url=_require(env, "ULLR_TOOLS_URL"), timeout=10.0),
            read_secret(env, "executor_token"),
        )
        gateway = _gateway(
            env,
            tools=tools,
            admin_token=None,
            approver_token=None,
            approvers=approvals.load_registry(_require(env, "ULLR_APPROVERS")),
            recover_on_start=True,
        )
        start_loop(gateway, float(env.get("ULLR_RECONCILE_INTERVAL", "5")))
        return create_agent_app(gateway)
    if role == "gateway-admin":
        gateway = _gateway(
            env,
            tools=None,
            admin_token=read_secret(env, "gateway_admin_token"),
            approver_token=None,
            approvers={},
            recover_on_start=False,
        )
        return create_admin_app(gateway)
    if role == "gateway-approver":
        gateway = _gateway(
            env,
            tools=None,
            admin_token=None,
            approver_token=read_secret(env, "approver_channel_token"),
            approvers=approvals.load_registry(_require(env, "ULLR_APPROVERS")),
            recover_on_start=False,
        )
        return create_approver_app(gateway)
    if role in ("tools-executor", "tools-admin"):
        db_path = _require(env, "ULLR_TOOLS_DB")
        _check_database(db_path)
        state = ToolsState(db_path)
        if role == "tools-executor":
            return tools_app.create_executor_app(state, read_secret(env, "executor_token"))
        return tools_app.create_admin_app(state, read_secret(env, "tools_admin_token"), Seed())
    if role == "llm-relay":
        models = frozenset(_require(env, "ULLR_ALLOWED_MODELS").split(","))
        upstream = httpx.Client(base_url=_require(env, "ULLR_OLLAMA_URL"), timeout=600.0)
        digests = check_upstream(upstream, models)
        print(json.dumps({"event": "relay_ready", "models": digests}), flush=True)
        return create_relay_app(upstream, models)
    raise ConfigError(f"ULLR_ROLE must be one of {', '.join(ROLES)}")


def main() -> int:
    try:
        app = build_app(os.environ)
    except (
        ConfigError,
        storage.StorageError,
        sqlite3.Error,
        httpx.HTTPError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"refusing to start: {exc}", file=sys.stderr, flush=True)
        return 1
    port = int(os.environ.get("ULLR_PORT", "8000"))
    # One purpose per container: reachability is decided by network membership.
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning", access_log=False)  # noqa: S104
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
