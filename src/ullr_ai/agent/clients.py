"""The two routings of the benchmark agent. Nothing else differs between them.

``GatewayClient`` proposes every tool call to the Gateway with the episode's
agent token. ``DirectToolsClient`` is the unprotected baseline: it calls the
Tools executor API of the baseline project with that project's own executor
token. Both forward whatever the model asked for, unknown tools included, and
return the service's reply unchanged.
"""

import secrets
import time
from collections.abc import Callable
from typing import Any

import httpx

from ullr_ai.gateway.policy import TOOL_TIERS


def _body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"error": "unreadable_reply"}


def _ms(seconds: float) -> float:
    return round(seconds * 1000, 1)


class GatewayClient:
    """Propose; if approval is required, poll execute for a bounded time.

    When the wait expires the model is given the pending reply and the action
    stays as it is in the Gateway: nothing is cancelled. Each call from the
    model is a new proposal; a repeated call is not merged with an earlier one.
    """

    def __init__(
        self,
        http: httpx.Client,
        agent_token: str,
        *,
        approval_wait: float = 20.0,
        poll: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._http = http
        self._headers = {"Authorization": f"Bearer {agent_token}"}
        self._approval_wait = approval_wait
        self._poll = poll
        self._clock = clock
        self._sleep = sleep

    def invoke(self, tool: str, resource_id: Any, args: Any, reason: str) -> dict[str, Any]:
        action = {"tool": tool, "resource_id": resource_id, "args": args}
        started = self._clock()
        try:
            proposal = self._http.post(
                "/v1/actions", json={**action, "reason": reason}, headers=self._headers
            )
        except httpx.HTTPError:
            return _unreachable(_ms(self._clock() - started))
        proposed = self._clock()
        reply = _body(proposal)
        latency = {"proposal": _ms(proposed - started), "execution": None, "approval_wait": None}
        outcome = {"http_status": proposal.status_code, "reply": reply, "execute_attempts": 0}

        pending = (
            proposal.status_code == 202
            and type(reply) is dict
            and reply.get("status") == "PENDING_APPROVAL"
        )
        if pending:
            path = f"/v1/actions/{reply['action_id']}"
            deadline = proposed + self._approval_wait
            while self._clock() < deadline:
                self._sleep(self._poll)
                attempt_started = self._clock()
                try:
                    attempt = self._http.post(path + "/execute", json=action, headers=self._headers)
                except httpx.HTTPError:
                    break
                outcome["execute_attempts"] += 1
                answer = _body(attempt)
                if attempt.status_code == 403 and answer == {"error": "approval_required"}:
                    continue
                latency["approval_wait"] = _ms(attempt_started - proposed)
                latency["execution"] = _ms(self._clock() - attempt_started)
                outcome |= {"http_status": attempt.status_code, "reply": answer}
                break
            else:
                latency["approval_wait"] = _ms(self._clock() - proposed)

        latency["end_to_end"] = round(latency["proposal"] + (latency["execution"] or 0.0), 1)
        return {**outcome, "latency_ms": latency}


class DirectToolsClient:
    """Unprotected baseline: the agent holds an executor token and calls the Tools service.

    The Tools service still requires an idempotency key and a version
    precondition for mutations, so the client supplies a fresh key and the
    current version, as any direct integration would. ``reason`` has no
    recipient here and is dropped.
    """

    def __init__(
        self,
        http: httpx.Client,
        executor_token: str,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http = http
        self._headers = {"Authorization": f"Bearer {executor_token}"}
        self._clock = clock

    def invoke(self, tool: str, resource_id: Any, args: Any, reason: str) -> dict[str, Any]:
        started = self._clock()
        headers = dict(self._headers)
        try:
            if TOOL_TIERS.get(tool, "R0") != "R0":
                version = 0
                if type(resource_id) is str:
                    meta = self._http.get(f"/v1/resources/{resource_id}", headers=self._headers)
                    if meta.status_code != 200:
                        return self._outcome(started, meta)
                    version = meta.json()["version"]
                headers |= {
                    "Idempotency-Key": "base_" + secrets.token_hex(16),
                    "If-Match": str(version),
                }
            response = self._http.post(
                "/v1/execute",
                json={"tool": tool, "resource_id": resource_id, "args": args},
                headers=headers,
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return _unreachable(_ms(self._clock() - started))
        return self._outcome(started, response)

    def _outcome(self, started: float, response: httpx.Response) -> dict[str, Any]:
        return {
            "http_status": response.status_code,
            "reply": _body(response),
            "latency_ms": {"end_to_end": _ms(self._clock() - started)},
        }


def _unreachable(elapsed_ms: float) -> dict[str, Any]:
    return {
        "http_status": None,
        "reply": {"error": "service_unreachable"},
        "latency_ms": {"end_to_end": elapsed_ms},
    }
