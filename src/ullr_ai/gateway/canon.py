"""Canon v1: strict JSON parsing, canonical JSON encoding, free-text rules, action hash.

SECURITY-CRITICAL: manual review required for any change to this module.

The rules are specified in docs/ARCHITECTURE.md section 4. Nothing here normalizes:
an input that is not already in canonical form is rejected. Any change of
behaviour requires a new CANON_VERSION, which invalidates outstanding approvals.
"""

import hashlib
import json
import unicodedata
from typing import Any

CANON_VERSION = 1

# NFC and general categories come from the interpreter's Unicode database.
# Canon v1 is defined against this exact version (Python 3.12).
UNICODE_VERSION = "15.0.0"
if unicodedata.unidata_version != UNICODE_VERSION:
    raise RuntimeError(
        f"canon v1 requires Unicode {UNICODE_VERSION}, found {unicodedata.unidata_version}"
    )

MAX_INT = 2**53 - 1
MAX_DEPTH = 32
MAX_BYTES = 262_144

# Longest decimal token of an in-range integer: "-9007199254740991".
_MAX_INT_TOKEN_LEN = 17

# Control, format (zero-width, bidi), surrogate, private-use, unassigned,
# line separator, paragraph separator.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class CanonError(ValueError):
    """Input rejected by canon v1."""


def _reject_float(token: str) -> Any:
    raise CanonError("floats are not allowed")


def _reject_constant(token: str) -> Any:
    raise CanonError(f"{token} is not allowed")


def _parse_int(token: str) -> int:
    if token == "-0":  # noqa: S105 (numeric token, not a secret)
        raise CanonError("negative zero is not allowed")
    if len(token) > _MAX_INT_TOKEN_LEN:
        raise CanonError("integer out of range")
    value = int(token)
    if not -MAX_INT <= value <= MAX_INT:
        raise CanonError("integer out of range")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise CanonError("duplicate key")
        obj[key] = value
    return obj


_DECODER = json.JSONDecoder(
    object_pairs_hook=_unique_pairs,
    parse_float=_reject_float,
    parse_int=_parse_int,
    parse_constant=_reject_constant,
    strict=True,
)


def _check_string(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonError("string is not valid Unicode (lone surrogate)") from None


def _check_value(value: Any, depth: int) -> None:
    """Accept only the JSON data model of canon v1, with exact Python types."""
    kind = type(value)
    if value is None or kind is bool:
        return
    if kind is str:
        _check_string(value)
        return
    if kind is int:
        if not -MAX_INT <= value <= MAX_INT:
            raise CanonError("integer out of range")
        return
    if kind is list or kind is dict:
        if depth >= MAX_DEPTH:
            raise CanonError("nesting too deep")
        if kind is list:
            for item in value:
                _check_value(item, depth + 1)
            return
        for key, item in value.items():
            if type(key) is not str:
                raise CanonError("object keys must be strings")
            _check_string(key)
            _check_value(item, depth + 1)
        return
    raise CanonError(f"type {kind.__name__} is not allowed")


def parse_json_strict(data: bytes) -> Any:
    """Parse UTF-8 JSON bytes, rejecting everything canon v1 does not allow.

    Rejected: non-bytes input, oversized input, invalid UTF-8, BOM, duplicate
    keys at any depth, NaN/Infinity, every float, -0, out-of-range integers,
    lone surrogates, excessive nesting, trailing data.
    """
    if type(data) is not bytes:
        raise CanonError("input must be bytes")
    if len(data) > MAX_BYTES:
        raise CanonError("input too large")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CanonError("input is not valid UTF-8") from None
    if text.startswith("\ufeff"):
        raise CanonError("byte order mark is not allowed")
    try:
        value = _DECODER.decode(text)
    except CanonError:
        raise
    except (ValueError, RecursionError):
        raise CanonError("invalid JSON") from None
    _check_value(value, 0)
    return value


def canonical_json(value: Any) -> bytes:
    """Encode a value as canonical JSON bytes.

    UTF-8, non-ASCII not escaped, keys sorted by Unicode code point, no
    insignificant whitespace. Floats and any non-JSON type are rejected.
    """
    _check_value(value, 0)
    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def check_text(text: Any, *, multiline: bool = False) -> str:
    """Validate a free-text value and return it unchanged.

    The text must be NFC and must not contain any character from the forbidden
    categories. U+000A is accepted only when ``multiline`` is true.
    """
    if type(text) is not str:
        raise CanonError("text must be a string")
    if not unicodedata.is_normalized("NFC", text):
        raise CanonError("text is not in NFC")
    for char in text:
        if multiline and char == "\n":
            continue
        if unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise CanonError(f"forbidden character U+{ord(char):04X}")
    return text


def action_hash(tool: str, resource_id: str | None, args: dict[str, Any]) -> str:
    """Hash of one canonical action. Callers pass already validated values."""
    preimage = canonical_json(
        {
            "args": args,
            "canon_version": CANON_VERSION,
            "resource_id": resource_id,
            "tool": tool,
        }
    )
    return "sha256:" + hashlib.sha256(preimage).hexdigest()
