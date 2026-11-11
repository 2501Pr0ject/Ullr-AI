"""Scripted agent of the demo, inside the agent container. No model is involved.

    python -m ullr_ai.demo.agent < script.json

The script is one JSON document, ``{"routing": "gateway" | "direct", "calls": [...]}``,
where each call is a tool call as a model would make it: ``{"name", "arguments"}``.
Each call goes through the benchmark agent's own code: ``tools.to_action`` turns
it into an action and the routing's client (``GatewayClient`` or
``DirectToolsClient``) sends it, exactly as in an L3 episode. Credentials are
read from the files the container was given, as ``ullr_ai.agent.run`` does, and
never printed. One JSON document is printed: the reply to each call.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from ullr_ai.agent import tools
from ullr_ai.agent.clients import DirectToolsClient, GatewayClient


def client_for(routing: str, env: dict[str, str]) -> Any:
    """The client of ``ullr_ai.agent.run`` for this routing."""
    if routing == "gateway":
        token = Path(env.get("ULLR_AGENT_TOKEN_FILE", "/run/episode/agent_token"))
        return GatewayClient(
            httpx.Client(base_url=env["ULLR_GATEWAY_URL"], timeout=60.0),
            token.read_text(encoding="ascii").strip(),
        )
    if routing == "direct":
        token = Path(env.get("ULLR_SECRETS_DIR", "/run/secrets")) / "executor_token"
        return DirectToolsClient(
            httpx.Client(base_url=env["ULLR_TOOLS_URL"], timeout=60.0),
            token.read_text(encoding="ascii").strip(),
        )
    raise ValueError(f"unknown routing: {routing}")


def play(client: Any, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Send each call in order and keep what came back. Nothing is decided here."""
    steps = []
    for call in calls:
        tool, resource_id, args, reason = tools.to_action(call["name"], call["arguments"])
        outcome = client.invoke(tool, resource_id, args, reason)
        steps.append(
            {
                "call": call,
                "http_status": outcome["http_status"],
                "reply": outcome["reply"],
                "raw_reply": outcome["raw_reply"],
                "execute_attempts": outcome.get("execute_attempts"),
            }
        )
    return steps


def main() -> int:
    script = json.loads(sys.stdin.read())
    client = client_for(script["routing"], dict(os.environ))
    steps = play(client, script["calls"])
    print(json.dumps({"routing": script["routing"], "steps": steps}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
