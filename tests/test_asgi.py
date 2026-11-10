"""Request size limit enforced at the ASGI layer, driven without an HTTP client."""

import asyncio
import json

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from ullr_ai.asgi import new_app

LIMIT = 10


def build_app(seen):
    app = new_app(LIMIT)

    @app.post("/echo-length")
    async def echo_length(request: Request) -> JSONResponse:
        body = await request.body()
        seen.append(len(body))
        return JSONResponse({"length": len(body)})

    return app


def call(app, chunks, headers):
    """Send one POST made of raw ASGI messages; return (status, body, receive calls)."""
    messages = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]
    sent = []
    receive_calls = 0

    async def receive():
        nonlocal receive_calls
        receive_calls += 1
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/echo-length",
        "raw_path": b"/echo-length",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "server": ("gateway", 80),
    }
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body), receive_calls


def test_body_within_the_limit_is_accepted():
    seen = []
    status, body, _ = call(build_app(seen), [b"0123456789"], [(b"content-length", b"10")])
    assert (status, body) == (200, {"length": 10})
    assert seen == [10]


def test_declared_length_above_the_limit_is_refused_without_reading_the_body():
    seen = []
    status, body, receive_calls = call(build_app(seen), [b"x" * 11], [(b"content-length", b"11")])
    assert (status, body) == (413, {"error": "request_too_large"})
    assert receive_calls == 0
    assert seen == []


def test_streamed_body_is_cut_off_when_it_crosses_the_limit():
    seen = []
    chunks = [b"abcd", b"efgh", b"ijkl", b"mnop", b"qrst"]
    status, body, receive_calls = call(build_app(seen), chunks, [])
    assert (status, body) == (413, {"error": "request_too_large"})
    assert receive_calls == 3  # stopped at the chunk that crossed the limit
    assert seen == []


def test_understated_content_length_does_not_bypass_the_limit():
    seen = []
    status, body, _ = call(build_app(seen), [b"x" * 6, b"x" * 6], [(b"content-length", b"5")])
    assert (status, body) == (413, {"error": "request_too_large"})
    assert seen == []


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"-1")],
        [(b"content-length", b"abc")],
        [(b"content-length", b"1e1")],
        [(b"content-length", b" 5")],
        [(b"content-length", b"")],
        [(b"content-length", b"9" * 13)],
        [(b"content-length", b"5"), (b"content-length", b"5")],
        [(b"content-length", b"5"), (b"content-length", b"50")],
    ],
)
def test_invalid_or_ambiguous_content_length_is_refused(headers):
    seen = []
    status, body, receive_calls = call(build_app(seen), [b"hello"], headers)
    assert (status, body) == (400, {"error": "invalid_request"})
    assert receive_calls == 0
    assert seen == []
