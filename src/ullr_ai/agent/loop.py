"""Tool-calling loop of the benchmark agent.

The same loop runs in both routings; only the client it is given differs. It
knows nothing about the Gateway or the Tools service: it sends chat requests
to the model, hands every tool call the model makes to the client, and gives
the client's reply back to the model unchanged.

Every tool call the model attempts is recorded, whether or not the tool exists.
"""

import json
import time
from collections.abc import Callable
from typing import Any, Protocol

Chat = Callable[[dict[str, Any]], dict[str, Any] | None]
ToAction = Callable[[str, Any], tuple[str, Any, Any, str]]


class Client(Protocol):
    def invoke(self, tool: str, resource_id: Any, args: Any, reason: str) -> dict[str, Any]:
        """Returns ``{"http_status", "reply", "latency_ms", ...}``."""


def run(
    chat: Chat,
    client: Client,
    *,
    model: str,
    system_prompt: str,
    first_message: str,
    tools: list[dict[str, Any]],
    to_action: ToAction,
    known_tools: frozenset[str],
    max_steps: int,
    options: dict[str, Any],
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run one episode. Returns ``{"end_reason", "request", "events"}``.

    ``max_steps`` bounds the tool calls forwarded to the client. ``chat``
    returns the model's reply, or None when the model could not be reached.
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": first_message},
    ]
    # What every chat request carries besides the messages: recorded once.
    fixed = {"model": model, "tools": tools, "stream": False, "think": False, "options": options}
    events: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    steps = 0

    def finish(reason: str) -> dict[str, Any]:
        request = {name: fixed[name] for name in ("model", "think", "options")}
        return {"end_reason": reason, "request": request, "events": events}

    turn = 0
    while True:
        if deadline is not None and clock() >= deadline:
            return finish("time_limit")
        turn += 1
        started = clock()
        reply = chat({**fixed, "messages": messages})
        elapsed = round((clock() - started) * 1000, 1)
        message = reply.get("message") if type(reply) is dict else None
        if type(message) is not dict:
            events.append({"type": "model_error", "turn": turn, "ms": elapsed})
            return finish("model_error")

        calls = message.get("tool_calls") or []
        content = message.get("content") or ""
        events.append(
            {
                "type": "model",
                "turn": turn,
                "ms": elapsed,
                "content": content,
                "tool_calls": calls,
                "eval_count": reply.get("eval_count"),
                "prompt_eval_count": reply.get("prompt_eval_count"),
            }
        )
        if not calls:
            return finish("final_answer")
        # Ollama gives each tool call a random id. It is kept in the transcript
        # but not sent back, so that the conversation depends on the seed only.
        echoed = [
            {k: v for k, v in call.items() if k != "id"} if type(call) is dict else call
            for call in calls
        ]
        messages.append({"role": "assistant", "content": content, "tool_calls": echoed})

        for call in calls:
            function = call.get("function") if type(call) is dict else None
            name = function.get("name") if type(function) is dict else None
            arguments = function.get("arguments") if type(function) is dict else None
            name = name if type(name) is str else ""
            event: dict[str, Any] = {
                "type": "tool_call",
                "turn": turn,
                "name": name,
                "arguments": arguments,
                "known_tool": name in known_tools,
            }
            events.append(event)
            if steps >= max_steps:
                # Attempted but not forwarded: the episode is over.
                event["forwarded"] = False
                continue
            steps += 1
            tool, resource_id, args, reason = to_action(name, arguments)
            signature = json.dumps([tool, resource_id, args], sort_keys=True, default=str)
            outcome = client.invoke(tool, resource_id, args, reason)
            event |= {
                "forwarded": True,
                "step": steps,
                "action": {"tool": tool, "resource_id": resource_id, "args": args},
                "reason": reason,
                # Step of the first identical call in this episode, if any.
                "repeat_of": seen.get(signature),
                **outcome,
            }
            seen.setdefault(signature, steps)
            messages.append(
                {
                    "role": "tool",
                    "tool_name": name,
                    "content": json.dumps(outcome["reply"], ensure_ascii=False),
                }
            )
        if steps >= max_steps:
            return finish("max_steps")
