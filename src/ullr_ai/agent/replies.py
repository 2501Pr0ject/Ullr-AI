"""What the model is shown after a tool call: one shape, in both routings.

``{"status": ...}`` with ``status`` one of ``executed``, ``refused``,
``rejected``, ``pending_approval`` or ``unknown``; ``result`` when executed;
``error`` (and sometimes ``reason``) when refused or rejected.

Trust labels and the provenance source list are removed: they are the
Gateway's inputs, not the agent's. The raw service reply stays in the
transcript and is never given to the model.
"""

from typing import Any

EXECUTED = "executed"
REFUSED = "refused"
REJECTED = "rejected"
PENDING = "pending_approval"
UNKNOWN = "unknown"

# The Gateway names a missing resource differently from the Tools service.
_ERROR_NAMES = {"resource_not_found": "not_found"}


def clean(value: Any) -> Any:
    """A tool result without any trust label, at any depth."""
    if type(value) is dict:
        return {k: clean(v) for k, v in value.items() if k != "trust_label"}
    if type(value) is list:
        return [clean(item) for item in value]
    return value


def _refused(error: Any, **extra: Any) -> dict[str, Any]:
    name = error if type(error) is str else "unexpected_reply"
    return {"status": REFUSED, "error": _ERROR_NAMES.get(name, name), **extra}


def unreachable() -> dict[str, Any]:
    return {"status": UNKNOWN}


def from_gateway(http_status: int, body: Any, action: dict[str, Any] | None = None) -> dict:
    """Normalize a Gateway reply. ``action`` is the status route's answer, if it was asked."""
    if type(body) is not dict:
        return _refused(None)
    status = body.get("status")
    if http_status == 200 and status == "COMMITTED":
        return {"status": EXECUTED, "result": clean(body.get("result"))}
    if status == "PENDING_APPROVAL":
        return {"status": PENDING}
    if status == "UNKNOWN":
        return {"status": UNKNOWN}
    if status == "DENIED":
        return _refused("denied_by_policy", reason=body.get("reason"))
    if action is not None and action.get("status") == "REJECTED":
        return {"status": REJECTED, "reason": action.get("reason")}
    return _refused(body.get("error"))


def from_tools(http_status: int, body: Any) -> dict[str, Any]:
    """Normalize a reply of the Tools executor API (baseline routing)."""
    if type(body) is not dict:
        return _refused(None)
    if http_status == 200 and body.get("executed") is True:
        return {"status": EXECUTED, "result": clean(body.get("result"))}
    if http_status >= 500:
        return {"status": UNKNOWN}
    return _refused(body.get("error"))
