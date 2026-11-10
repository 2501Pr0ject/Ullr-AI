"""HTTP plumbing shared by the Gateway and the Tools service.

Responses built here carry fixed error codes only: nothing from the request
is ever echoed back.
"""

import hmac
import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyTooLarge(Exception):
    """The request body exceeded the configured limit while being read."""


def error(status: int, code: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": code, **extra}, status_code=status)


class BodyLimitMiddleware:
    """Reject oversized request bodies at the ASGI layer, before any parsing.

    A declared Content-Length above the limit is refused without reading the
    body. A body without a (truthful) Content-Length is counted while it is
    received and the read is aborted as soon as the limit is crossed.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = [value for name, value in scope["headers"] if name == b"content-length"]
        if declared:
            if len(declared) > 1 or not declared[0].isdigit() or len(declared[0]) > 12:
                await _send_error(send, 400, "invalid_request")
                return
            if int(declared[0]) > self.max_bytes:
                await _send_error(send, 413, "request_too_large")
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise BodyTooLarge
            return message

        await self.app(scope, limited_receive, send)


async def _send_error(send: Send, status: int, code: str) -> None:
    body = json.dumps({"error": code}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def new_app(max_body_bytes: int) -> FastAPI:
    """A FastAPI app with the body limit and input-free error responses."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(BodyLimitMiddleware, max_bytes=max_body_bytes)

    @app.exception_handler(BodyTooLarge)
    async def _too_large(request: Request, exc: BodyTooLarge) -> JSONResponse:
        return error(413, "request_too_large")

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return error(400, "invalid_request")

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
        return error(exc.status_code, code)

    @app.exception_handler(Exception)
    async def _internal(request: Request, exc: Exception) -> JSONResponse:
        return error(500, "internal_error")

    return app


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header is None or not header.startswith("Bearer "):
        return None
    return header[len("Bearer ") :]


def token_matches(presented: str | None, expected: str) -> bool:
    if presented is None:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))
