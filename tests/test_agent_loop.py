"""Agent loop: fixed request settings, every attempted tool call recorded, bounded steps."""

import json

from ullr_ai.agent import loop

OPTIONS = {"temperature": 0, "seed": 20261115}


def call(name, **arguments):
    return {"function": {"name": name, "arguments": arguments}}


def model(*tool_calls, content=""):
    return {"message": {"role": "assistant", "content": content, "tool_calls": list(tool_calls)}}


class Script:
    """A model that answers from a list, and records every request it receives."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, request):
        self.requests.append(json.loads(json.dumps(request)))
        return self.replies.pop(0)


class Recorder:
    def __init__(self):
        self.calls = []

    def invoke(self, tool, resource_id, args, reason):
        self.calls.append((tool, resource_id, args, reason))
        return {"http_status": 200, "reply": {"n": len(self.calls)}, "latency_ms": {}}


def to_action(name, arguments):
    fields = dict(arguments or {})
    return name, fields.pop("id", None), fields, fields.pop("reason", "")


def run(script, client, max_steps=20, **overrides):
    settings = {
        "model": "qwen3:8b",
        "system_prompt": "SYSTEM",
        "first_message": "REQUEST",
        "tools": [{"type": "function", "function": {"name": "read_document"}}],
        "to_action": to_action,
        "known_tools": frozenset({"read_document", "send_email"}),
        "max_steps": max_steps,
        "options": OPTIONS,
        **overrides,
    }
    return loop.run(script, client, **settings)


def tool_events(transcript):
    return [e for e in transcript["events"] if e["type"] == "tool_call"]


def test_every_chat_request_carries_the_same_fixed_settings():
    script = Script(model(call("read_document", id="doc_1")), model(content="Done."))
    transcript = run(script, Recorder())
    assert transcript["end_reason"] == "final_answer"
    assert transcript["request"] == {"model": "qwen3:8b", "think": False, "options": OPTIONS}
    assert len(script.requests) == 2
    for request in script.requests:
        assert request["model"] == "qwen3:8b"
        assert request["think"] is False
        assert request["stream"] is False
        assert request["options"] == OPTIONS
        assert request["tools"] == [{"type": "function", "function": {"name": "read_document"}}]
    assert script.requests[0]["messages"] == [
        {"role": "system", "content": "SYSTEM"},
        {"role": "user", "content": "REQUEST"},
    ]


def test_think_is_sent_as_given_or_not_at_all():
    for think, recorded in ((True, True), (False, False), (None, "not_sent")):
        script = Script(model(content="Done."))
        transcript = run(script, Recorder(), think=think)
        assert transcript["request"]["think"] == recorded
        if think is None:
            assert "think" not in script.requests[0]
        else:
            assert script.requests[0]["think"] is think


def test_episode_time_runs_from_the_first_model_request_to_the_end():
    ticks = iter(range(0, 1000, 2))
    script = Script(model(call("read_document", id="doc_1")), model(content="Done."))
    transcript = run(script, Recorder(), clock=lambda: next(ticks))
    assert transcript["agent_ms"] > 0
    assert transcript["agent_ms"] >= sum(
        e["ms"] for e in transcript["events"] if e["type"] == "model"
    )


def test_thinking_text_is_recorded_and_not_sent_back():
    reply = model(call("read_document", id="doc_1"))
    reply["message"]["thinking"] = "The user wants doc_1."
    script = Script(reply, model(content="Done."))
    transcript = run(script, Recorder(), think=True)
    assert transcript["events"][0]["thinking"] == "The user wants doc_1."
    assert "thinking" not in script.requests[1]["messages"][2]


def test_tool_reply_goes_back_to_the_model_unchanged():
    script = Script(model(call("read_document", id="doc_1")), model(content="Done."))
    run(script, Recorder())
    assistant, tool = script.requests[1]["messages"][2:]
    assert assistant["tool_calls"] == [call("read_document", id="doc_1")]
    assert tool == {"role": "tool", "tool_name": "read_document", "content": '{"n": 1}'}


def test_random_call_id_is_recorded_but_not_sent_back_to_the_model():
    with_id = {"id": "call_gd16il9j", **call("read_document", id="doc_1")}
    script = Script(model(with_id), model(content="Done."))
    transcript = run(script, Recorder())
    assert transcript["events"][0]["tool_calls"] == [with_id]
    assert script.requests[1]["messages"][2]["tool_calls"] == [call("read_document", id="doc_1")]


def test_unknown_tool_is_forwarded_and_recorded():
    script = Script(
        model(call("admin_execute", command="disable"), call("send_email", to="x")), model()
    )
    client = Recorder()
    events = tool_events(run(script, client))
    assert client.calls[0] == ("admin_execute", None, {"command": "disable"}, "")
    assert [(e["name"], e["known_tool"], e["forwarded"]) for e in events] == [
        ("admin_execute", False, True),
        ("send_email", True, True),
    ]
    assert events[0]["arguments"] == {"command": "disable"}
    assert events[0]["reply"] == {"n": 1}


def test_max_steps_bounds_forwarded_calls_and_keeps_the_attempts():
    script = Script(
        model(call("read_document", id="doc_1"), call("read_document", id="doc_2")),
        model(call("send_email", to="a"), call("send_email", to="b")),
        model(content="never asked"),
    )
    client = Recorder()
    transcript = run(script, client, max_steps=3)
    assert transcript["end_reason"] == "max_steps"
    assert len(client.calls) == 3
    assert [e["forwarded"] for e in tool_events(transcript)] == [True, True, True, False]
    assert len(script.requests) == 2


def test_repeated_identical_call_is_marked():
    script = Script(
        model(call("send_email", to="contact_1", reason="first")),
        model(call("read_document", id="doc_1")),
        model(call("send_email", to="contact_1", reason="again")),
        model(),
    )
    client = Recorder()
    events = tool_events(run(script, client))
    assert [e["repeat_of"] for e in events] == [None, None, 1]
    assert [e["step"] for e in events] == [1, 2, 3]
    assert len(client.calls) == 3  # a repeat is still forwarded, as a new call


def test_model_failure_ends_the_episode():
    for reply in (None, {}, {"message": "text"}):
        transcript = run(Script(reply), Recorder())
        assert transcript["end_reason"] == "model_error"
        assert transcript["events"][-1]["type"] == "model_error"
    transcript = run(Script({"error": "request_timeout"}), Recorder())
    assert transcript["events"][-1]["error"] == "request_timeout"


def test_malformed_tool_call_is_recorded_and_forwarded_as_an_unknown_tool():
    script = Script(model({"function": {"arguments": {"x": 1}}}, "garbage"), model())
    client = Recorder()
    events = tool_events(run(script, client))
    assert [(e["name"], e["known_tool"]) for e in events] == [("", False), ("", False)]
    assert len(client.calls) == 2


def test_time_limit_is_checked_before_each_model_turn():
    ticks = iter(range(100))
    script = Script(model(call("read_document", id="doc_1")), model(call("read_document", id="d")))
    transcript = run(script, Recorder(), deadline=3, clock=lambda: next(ticks))
    assert transcript["end_reason"] == "time_limit"
    assert len(script.requests) == 1
