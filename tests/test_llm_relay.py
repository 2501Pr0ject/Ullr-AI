"""LLM relay contract: one route, one upstream, allow-listed model and fields."""

import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from ullr_ai.llm_relay import FORBIDDEN_ROUTES, check_upstream, create_relay_app

MODELS = frozenset({"qwen3:8b"})
CHAT = {
    "model": "qwen3:8b",
    "messages": [{"role": "user", "content": "hello"}],
    "think": False,
}


@pytest.fixture
def relay():
    """A relay in front of a recording fake upstream."""
    seen = []

    def upstream(request):
        seen.append(request)
        if request.url.path == "/api/chat":
            reply = {"model": "qwen3:8b", "message": {"role": "assistant", "content": "hi"}}
            return httpx.Response(200, json=reply)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(upstream), base_url="http://upstream")
    app = TestClient(create_relay_app(client, MODELS), base_url="http://relay")
    return app, seen


def test_valid_chat_is_forwarded_to_the_fixed_upstream(relay):
    app, seen = relay
    response = app.post("/api/chat", json=CHAT)
    assert response.status_code == 200
    assert response.json()["message"]["content"] == "hi"
    assert len(seen) == 1
    assert (seen[0].method, str(seen[0].url)) == ("POST", "http://upstream/api/chat")
    assert json.loads(seen[0].content) == {**CHAT, "stream": False}


def test_think_tools_and_options_are_forwarded(relay):
    app, seen = relay
    body = {
        **CHAT,
        "think": True,
        "tools": [{"type": "function", "function": {"name": "read_document"}}],
        "options": {"temperature": 0.0, "seed": 7, "num_ctx": 8192},
    }
    assert app.post("/api/chat", json=body).status_code == 200
    assert json.loads(seen[0].content) == {**body, "stream": False}


def test_stream_is_always_off_upstream(relay):
    app, seen = relay
    assert app.post("/api/chat", json={**CHAT, "stream": False}).status_code == 200
    assert json.loads(seen[0].content)["stream"] is False
    assert app.post("/api/chat", json={**CHAT, "stream": True}).status_code == 400
    assert len(seen) == 1


@pytest.mark.parametrize(
    "model", ["qwen3:8b-fast", "qwen3", "llama3.1:8b", "QWEN3:8B", "", None, 3]
)
def test_model_outside_the_allow_list_is_refused(relay, model):
    app, seen = relay
    response = app.post("/api/chat", json={**CHAT, "model": model})
    assert response.status_code == 403
    assert response.json() == {"error": "model_not_allowed"}
    assert seen == []


@pytest.mark.parametrize(
    "body",
    [
        {**CHAT, "keep_alive": "24h"},
        {**CHAT, "format": "json"},
        {**CHAT, "url": "http://example.com"},
        {**CHAT, "host": "host.docker.internal:22"},
        {**CHAT, "upstream": "http://169.254.169.254/"},
        {**CHAT, "think": "high"},
        {**CHAT, "options": {"temperature": 0.0, "num_gpu": 0}},
        {**CHAT, "options": {"temperature": "hot"}},
        {**CHAT, "options": []},
        {**CHAT, "tools": "all"},
        {**CHAT, "messages": []},
        {**CHAT, "messages": "hello"},
        {**CHAT, "messages": [{"role": "user", "content": "x", "images": ["AAAA"]}]},
        {**CHAT, "messages": [{"role": "root", "content": "x"}]},
        {**CHAT, "messages": [{"role": "user", "content": 5}]},
        {"messages": CHAT["messages"]},
        [],
        "chat",
    ],
)
def test_request_outside_the_contract_is_refused(relay, body):
    app, seen = relay
    response = app.post("/api/chat", json=body)
    assert response.status_code in (400, 403)
    assert seen == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b'{"model":"qwen3:8b","model":"llama3.1:8b","messages":[{"role":"user","content":"x"}]}',
        b'{"model":"qwen3:8b","messages":[{"role":"user","content":"x"}],"options":{"seed":NaN}}',
        b'\xff{"model":"qwen3:8b"}',
    ],
)
def test_malformed_body_is_refused(relay, raw):
    app, seen = relay
    assert app.post("/api/chat", content=raw).status_code == 400
    assert seen == []


def test_oversized_body_is_refused_before_forwarding():
    seen = []
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: seen.append(request)),
        base_url="http://upstream",
    )
    app = TestClient(create_relay_app(client, MODELS, max_body_bytes=2048))
    big = {**CHAT, "messages": [{"role": "user", "content": "x" * 4096}]}
    assert app.post("/api/chat", json=big).status_code == 413
    assert seen == []


@pytest.mark.parametrize("route", [r for r in FORBIDDEN_ROUTES if "{" not in r])
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_model_management_routes_are_refused_explicitly(relay, route, method):
    app, seen = relay
    response = app.request(method, route, json={"model": "qwen3:8b", "name": "qwen3:8b"})
    assert response.status_code == 403
    assert response.json() == {"error": "route_forbidden"}
    assert seen == []


def test_blob_routes_are_refused(relay):
    app, seen = relay
    assert app.post("/api/blobs/sha256:abc", content=b"x").status_code == 403
    assert app.head("/api/blobs/sha256:abc").status_code == 403
    assert seen == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/"),
        ("GET", "/api/chat"),
        ("PUT", "/api/chat"),
        ("POST", "/api/chat/extra"),
        ("POST", "/v1/chat/completions"),
        ("POST", "/api/../api/pull"),
        ("GET", "/admin/sessions"),
        ("POST", "//host.docker.internal:22/"),
    ],
)
def test_no_other_route_exists(relay, method, path):
    app, seen = relay
    assert app.request(method, path, json=CHAT).status_code in (403, 404, 405)
    assert seen == []


def test_request_headers_cannot_change_the_destination(relay):
    app, seen = relay
    headers = {
        "Host": "host.docker.internal:22",
        "X-Forwarded-Host": "169.254.169.254",
        "X-Upstream": "http://example.com",
    }
    assert app.post("/api/chat", json=CHAT, headers=headers).status_code == 200
    assert str(seen[0].url) == "http://upstream/api/chat"
    assert "x-upstream" not in seen[0].headers
    assert seen[0].headers["host"] == "upstream"


def test_upstream_redirect_is_not_followed():
    seen = []

    def upstream(request):
        seen.append(str(request.url))
        return httpx.Response(307, headers={"Location": "http://example.com/api/chat"})

    client = httpx.Client(transport=httpx.MockTransport(upstream), base_url="http://upstream")
    app = TestClient(create_relay_app(client, MODELS))
    response = app.post("/api/chat", json=CHAT)
    assert response.status_code == 502
    assert seen == ["http://upstream/api/chat"]


def test_upstream_failure_is_a_plain_error():
    def down(request):
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(down), base_url="http://upstream")
    app = TestClient(create_relay_app(client, MODELS))
    response = app.post("/api/chat", json=CHAT)
    assert response.status_code == 502
    assert response.json() == {"error": "upstream_unavailable"}


def test_start_up_check_returns_the_model_digest():
    def upstream(request):
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.0.0"})
        models = [{"name": "qwen3:8b", "digest": "abc123"}, {"name": "other", "digest": "x"}]
        return httpx.Response(200, json={"models": models})

    client = httpx.Client(transport=httpx.MockTransport(upstream), base_url="http://upstream")
    assert check_upstream(client, MODELS) == {"qwen3:8b": "abc123"}
    with pytest.raises(RuntimeError, match="allowed model"):
        check_upstream(client, frozenset({"missing:1b"}))


def test_start_up_check_fails_when_the_upstream_is_unreachable():
    def down(request):
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(down), base_url="http://upstream")
    with pytest.raises(httpx.HTTPError):
        check_upstream(client, MODELS)


# --- determinism through the relay (needs the real model) -----------------------

OLLAMA_URL = os.environ.get("ULLR_TEST_OLLAMA_URL")


@pytest.mark.skipif(OLLAMA_URL is None, reason="set ULLR_TEST_OLLAMA_URL to run against Ollama")
def test_same_seed_and_temperature_zero_give_identical_outputs_through_the_relay():
    """Two identical requests, tools included, through the relay code to a real Ollama."""
    from ullr_ai.agent import prompt, tools

    upstream = httpx.Client(base_url=OLLAMA_URL, timeout=600.0)
    check_upstream(upstream, MODELS)
    app = TestClient(create_relay_app(upstream, MODELS), base_url="http://relay")
    request = {
        "model": "qwen3:8b",
        "think": False,
        "options": {"temperature": 0, "seed": 20261115},
        "tools": tools.definitions(),
        "messages": [
            {"role": "system", "content": prompt.SYSTEM_PROMPT},
            {"role": "user", "content": "Request from the user:\nList the documents, then stop."},
        ],
    }
    replies = [app.post("/api/chat", json=request) for _ in range(2)]
    assert [reply.status_code for reply in replies] == [200, 200]
    first, second = (reply.json()["message"] for reply in replies)
    assert first.get("content") or first.get("tool_calls")

    def without_call_ids(message):
        calls = [{k: v for k, v in c.items() if k != "id"} for c in message.get("tool_calls", [])]
        return {**message, "tool_calls": calls}

    # Ollama attaches a random id to each tool call. It is not model output: the
    # text, the tools called and their arguments must be identical.
    assert without_call_ids(first) == without_call_ids(second)
