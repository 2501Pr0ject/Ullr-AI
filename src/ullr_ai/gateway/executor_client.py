"""Gateway-side client of the Tools executor API. Holds the executor token.

Every outcome falls in one of three classes:
- executed: the Tools service confirmed the execution;
- not executed: the Tools service confirmed a non-execution, with a known code;
- ambiguous: anything else (timeout, connection error, unexpected status or
  body). ``ToolsError`` is raised and the caller must not assume either way.
"""

from dataclasses import dataclass
from typing import Any

import httpx

from ullr_ai.gateway.canon import CanonError, parse_json_strict

# Error codes for which the Tools service guarantees that nothing was executed.
# ``idempotency_key_reuse`` is deliberately absent: it says nothing about the
# original request.
CONFIRMED_NOT_EXECUTED = frozenset(
    {
        "unauthorized",
        "invalid_request",
        "idempotency_key_required",
        "precondition_required",
        "precondition_failed",
        "not_found",
        "unknown_contact",
        "currency_mismatch",
    }
)


class ToolsError(Exception):
    """The outcome of a call to the Tools service is unknown."""


@dataclass(frozen=True)
class ToolsResult:
    executed: bool
    result: dict[str, Any] | None = None
    sources: tuple[tuple[str, str], ...] = ()
    error: str | None = None


class ExecutorClient:
    def __init__(self, http: httpx.Client, executor_token: str) -> None:
        self._http = http
        self._headers = {"Authorization": f"Bearer {executor_token}"}

    def _json(self, response: httpx.Response) -> dict[str, Any]:
        try:
            body = parse_json_strict(response.content)
        except CanonError:
            raise ToolsError("unreadable response") from None
        if type(body) is not dict:
            raise ToolsError("unexpected response")
        return body

    def resource_meta(self, resource_id: str) -> dict[str, Any] | None:
        """Version and trust label of a resource; None if it does not exist."""
        try:
            response = self._http.get(f"/v1/resources/{resource_id}", headers=self._headers)
        except httpx.HTTPError:
            raise ToolsError("tools service unreachable") from None
        body = self._json(response)
        if response.status_code == 404 and body == {"error": "not_found"}:
            return None
        if (
            response.status_code != 200
            or body.get("id") != resource_id
            or type(body.get("version")) is not int
            or body.get("trust_label") not in ("internal", "external")
        ):
            raise ToolsError("unexpected response")
        return body

    def execute(
        self,
        tool: str,
        resource_id: str | None,
        args: dict[str, str],
        *,
        idempotency_key: str | None = None,
        if_match: int | None = None,
    ) -> ToolsResult:
        headers = dict(self._headers)
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        if if_match is not None:
            headers["If-Match"] = str(if_match)
        try:
            response = self._http.post(
                "/v1/execute",
                json={"tool": tool, "resource_id": resource_id, "args": args},
                headers=headers,
            )
        except httpx.HTTPError:
            raise ToolsError("tools service unreachable") from None
        body = self._json(response)

        if response.status_code == 200 and body.get("executed") is True:
            result = body.get("result")
            if type(result) is not dict:
                raise ToolsError("unexpected response")
            if idempotency_key is not None:
                return ToolsResult(True, result=result)
            # A read: the trust labels are mandatory. Without them the session's
            # provenance cannot be derived, so the content must not be used.
            if "sources" not in body:
                raise ToolsError("read without trust labels")
            return ToolsResult(True, result=result, sources=_sources(body["sources"]))
        if (
            response.status_code != 200
            and body.get("executed") is False
            and body.get("error") in CONFIRMED_NOT_EXECUTED
        ):
            return ToolsResult(False, error=body["error"])
        raise ToolsError("ambiguous outcome")


def _sources(raw: Any) -> tuple[tuple[str, str], ...]:
    if type(raw) is not list:
        raise ToolsError("unexpected response")
    sources = []
    for item in raw:
        if (
            type(item) is not dict
            or set(item) != {"id", "trust_label"}
            or type(item["id"]) is not str
            or item["trust_label"] not in ("internal", "external")
        ):
            raise ToolsError("unexpected response")
        sources.append((item["id"], item["trust_label"]))
    return tuple(sources)
