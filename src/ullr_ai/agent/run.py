"""Entry point of the benchmark agent, inside the agent container.

    python -m ullr_ai.agent.run < episode.json

The episode is one JSON document on stdin: ``routing`` (``gateway`` or
``direct``), ``first_message``, ``max_steps``, ``model``, ``seed``,
``temperature`` and ``time_limit``. The transcript is printed as one JSON
document. Service addresses come from the environment; credentials are read
from the files the container was given, and never printed.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from ullr_ai.agent import loop, prompt, tools
from ullr_ai.agent.clients import DirectToolsClient, GatewayClient


def main() -> int:
    episode = json.loads(sys.stdin.read())
    env = os.environ
    relay = httpx.Client(base_url=env["ULLR_RELAY_URL"], timeout=600.0)

    def chat(request: dict[str, Any]) -> dict[str, Any] | None:
        try:
            response = relay.post("/api/chat", json=request)
            return response.json() if response.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None

    if episode["routing"] == "gateway":
        token = Path(env.get("ULLR_AGENT_TOKEN_FILE", "/run/episode/agent_token"))
        client: Any = GatewayClient(
            httpx.Client(base_url=env["ULLR_GATEWAY_URL"], timeout=60.0),
            token.read_text(encoding="ascii").strip(),
        )
    elif episode["routing"] == "direct":
        token = Path(env.get("ULLR_SECRETS_DIR", "/run/secrets")) / "executor_token"
        client = DirectToolsClient(
            httpx.Client(base_url=env["ULLR_TOOLS_URL"], timeout=60.0),
            token.read_text(encoding="ascii").strip(),
        )
    else:
        print("unknown routing", file=sys.stderr)
        return 2

    transcript = loop.run(
        chat,
        client,
        model=episode["model"],
        system_prompt=prompt.SYSTEM_PROMPT,
        first_message=episode["first_message"],
        tools=tools.definitions(),
        to_action=tools.to_action,
        known_tools=tools.KNOWN_TOOLS,
        max_steps=episode["max_steps"],
        options={"temperature": episode["temperature"], "seed": episode["seed"]},
        deadline=time.monotonic() + episode["time_limit"],
    )
    transcript["system_prompt_hash"] = prompt.system_prompt_hash()
    transcript["tool_definitions_hash"] = tools.definitions_hash()
    print(json.dumps(transcript, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
