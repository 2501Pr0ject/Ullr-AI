"""Role wiring: one application per process, only that role's secrets, from files."""

from pathlib import Path

import httpx
import pytest

from conftest import APPROVER_PUBLIC, DEFAULT_POLICY
from ullr_ai import serve
from ullr_ai.asgi import token_matches

SECRETS = {
    "executor_token": "executor-" + "e" * 40,
    "tools_admin_token": "tools-admin-" + "t" * 40,
    "gateway_admin_token": "gateway-admin-" + "g" * 40,
    "approver_channel_token": "approver-channel-" + "a" * 40,
}
ROLE_SECRETS = {
    "gateway-api": ["executor_token"],
    "gateway-admin": ["gateway_admin_token"],
    "gateway-approver": ["approver_channel_token"],
    "tools-executor": ["executor_token"],
    "tools-admin": ["tools_admin_token"],
}
ROLE_ROUTES = {
    "gateway-api": {
        ("POST", "/v1/actions"),
        ("POST", "/v1/actions/{action_id}/execute"),
        ("GET", "/v1/actions/{action_id}"),
    },
    "gateway-admin": {
        ("POST", "/admin/sessions"),
        ("POST", "/admin/sessions/{session_id}/revoke"),
        ("GET", "/admin/state"),
    },
    "gateway-approver": {
        ("GET", "/v1/approvals"),
        ("GET", "/v1/approvals/{action_id}"),  # read-only status of a decided request
        ("POST", "/v1/approvals/{action_id}/decision"),
    },
    "tools-executor": {
        ("POST", "/v1/execute"),
        ("GET", "/v1/resources/{resource_id}"),
        ("GET", "/v1/executions/{idempotency_key}"),
        ("POST", "/v1/executions/{idempotency_key}/resolve"),
    },
}


def routes(app):
    return {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", ())
        if method != "HEAD"
    }


@pytest.fixture
def base_env(tmp_path):
    registry = tmp_path / "approvers.yaml"
    registry.write_text(f'approvers:\n  human_1: "{APPROVER_PUBLIC}"\n', encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    return {
        "ULLR_SECRETS_DIR": str(tmp_path / "secrets"),
        "ULLR_GATEWAY_DB": str(tmp_path / "gateway.db"),
        "ULLR_TOOLS_DB": str(tmp_path / "tools.db"),
        "ULLR_POLICY": str(DEFAULT_POLICY),
        "ULLR_APPROVERS": str(registry),
        "ULLR_TOOLS_URL": "http://tools-executor:8000",
        "ULLR_RECONCILE_INTERVAL": "3600",
    }


def give(env, names):
    for name in names:
        path = Path(env["ULLR_SECRETS_DIR"]) / name
        path.write_text(SECRETS[name] + "\n", encoding="ascii")


@pytest.mark.parametrize("role", sorted(ROLE_ROUTES))
def test_each_role_serves_exactly_its_own_routes(base_env, role):
    give(base_env, ROLE_SECRETS[role])
    app = serve.build_app({**base_env, "ULLR_ROLE": role})
    assert routes(app) == ROLE_ROUTES[role]


@pytest.mark.parametrize("role", sorted(ROLE_SECRETS))
def test_each_role_starts_with_only_its_own_secrets(base_env, role):
    """No role needs a secret that the topology does not give it."""
    give(base_env, ROLE_SECRETS[role])
    serve.build_app({**base_env, "ULLR_ROLE": role})


@pytest.mark.parametrize("role", sorted(ROLE_SECRETS))
def test_role_refuses_to_start_without_its_secret(base_env, role):
    others = [name for name in SECRETS if name not in ROLE_SECRETS[role]]
    give(base_env, others)
    with pytest.raises(serve.ConfigError, match="not available"):
        serve.build_app({**base_env, "ULLR_ROLE": role})


def test_secrets_are_not_read_from_the_environment(base_env):
    env = {
        **base_env,
        "ULLR_ROLE": "gateway-admin",
        "gateway_admin_token": SECRETS["gateway_admin_token"],
        "GATEWAY_ADMIN_TOKEN": SECRETS["gateway_admin_token"],
    }
    with pytest.raises(serve.ConfigError):
        serve.build_app(env)


def test_short_secret_is_refused(base_env, tmp_path):
    (tmp_path / "secrets" / "gateway_admin_token").write_text("short\n", encoding="ascii")
    with pytest.raises(serve.ConfigError, match="too short"):
        serve.build_app({**base_env, "ULLR_ROLE": "gateway-admin"})


@pytest.mark.parametrize("role", [None, "", "gateway", "agent", "controller", "GATEWAY-API"])
def test_unknown_role_is_refused(base_env, role):
    env = dict(base_env)
    if role is not None:
        env["ULLR_ROLE"] = role
    with pytest.raises(serve.ConfigError, match="ULLR_ROLE"):
        serve.build_app(env)


def test_admin_and_approver_processes_cannot_reach_the_tools_service(base_env):
    """They hold no executor token and no Tools client."""
    give(base_env, ["gateway_admin_token", "approver_channel_token"])
    for role in ("gateway-admin", "gateway-approver"):
        env = {key: value for key, value in base_env.items() if key != "ULLR_TOOLS_URL"}
        app = serve.build_app({**env, "ULLR_ROLE": role})
        assert all("execute" not in path for _, path in routes(app))


def test_api_process_holds_neither_admin_nor_approver_token(base_env, monkeypatch):
    give(base_env, ["executor_token"])
    captured = {}
    original = serve.Gateway

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(serve, "Gateway", spy)
    serve.build_app({**base_env, "ULLR_ROLE": "gateway-api"})
    assert captured["admin_token"] is None
    assert captured["approver_token"] is None
    assert captured["recover_on_start"] is True


def test_missing_token_never_matches():
    for presented in (None, "", "None", "null"):
        assert not token_matches(presented, None)
        assert not token_matches(presented, "")


def test_relay_refuses_to_start_when_the_upstream_is_unreachable(base_env, monkeypatch):
    def unreachable(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(serve, "check_upstream", unreachable)
    env = {
        **base_env,
        "ULLR_ROLE": "llm-relay",
        "ULLR_OLLAMA_URL": "http://host.docker.internal:11434",
        "ULLR_ALLOWED_MODELS": "qwen3:8b",
    }
    with pytest.raises(httpx.HTTPError):
        serve.build_app(env)


def test_database_without_wal_is_refused_at_start_up(base_env):
    give(base_env, ["gateway_admin_token"])
    env = {**base_env, "ULLR_ROLE": "gateway-admin", "ULLR_GATEWAY_DB": ":memory:"}
    with pytest.raises(serve.storage.StorageError):
        serve.build_app(env)
