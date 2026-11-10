"""Exact tool allow-list and strict per-tool argument schemas (ARCHITECTURE.md section 4).

Every tool acts on at most one opaque resource. Anything that is not exactly
in the expected form is rejected: no coercion, no unknown field, no alias.
"""

import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, ValidationError

from ullr_ai.gateway.canon import CanonError, action_hash, check_text


class SchemaError(ValueError):
    """Action rejected by the tool schemas."""


def _full_match(regex: str) -> AfterValidator:
    # re.fullmatch on an ASCII-only pattern: no trailing newline, no Unicode digits.
    compiled = re.compile(regex)

    def check(value: str) -> str:
        if compiled.fullmatch(value) is None:
            raise ValueError("value does not match the required format")
        return value

    return AfterValidator(check)


def _free_text(max_length: int, *, multiline: bool = False) -> AfterValidator:
    def check(value: str) -> str:
        if not 1 <= len(value) <= max_length:
            raise ValueError("text length out of bounds")
        return check_text(value, multiline=multiline)

    return AfterValidator(check)


def _positive(value: str) -> str:
    if value == "0.00":
        raise ValueError("amount must be strictly positive")
    return value


DOC_ID = r"doc_[0-9]{1,8}"
ACCOUNT_ID = r"acct_[0-9]{1,8}"
CONFIG_ID = r"cfg_[0-9]{1,8}"
CONTACT_ID = r"contact_[0-9]{1,8}"

ContactId = Annotated[str, _full_match(CONTACT_ID)]
Amount = Annotated[str, _full_match(r"(0|[1-9][0-9]{0,6})\.[0-9]{2}"), AfterValidator(_positive)]
Currency = Literal["EUR", "USD", "GBP"]

Subject = Annotated[str, _free_text(200)]
Body = Annotated[str, _free_text(20_000, multiline=True)]
Content = Annotated[str, _free_text(20_000, multiline=True)]
ConfigValue = Annotated[str, _free_text(2_000)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class NoArgs(StrictModel):
    pass


class UpdateDocumentArgs(StrictModel):
    content: Content


class EmailArgs(StrictModel):
    to: ContactId
    subject: Subject
    body: Body


class IssueRefundArgs(StrictModel):
    amount: Amount
    currency: Currency


class UpdateProdConfigArgs(StrictModel):
    value: ConfigValue


@dataclass(frozen=True)
class ToolSpec:
    resource: re.Pattern[str] | None  # None: the tool takes no resource, resource_id must be null
    args: type[StrictModel]


def _spec(resource: str | None, args: type[StrictModel]) -> ToolSpec:
    return ToolSpec(re.compile(resource) if resource is not None else None, args)


TOOLS: dict[str, ToolSpec] = {
    "read_document": _spec(DOC_ID, NoArgs),
    "list_documents": _spec(None, NoArgs),
    "read_inbox": _spec(None, NoArgs),
    "get_balance": _spec(ACCOUNT_ID, NoArgs),
    "draft_email": _spec(None, EmailArgs),
    "update_document": _spec(DOC_ID, UpdateDocumentArgs),
    "send_email": _spec(None, EmailArgs),
    "delete_document": _spec(DOC_ID, NoArgs),
    "issue_refund": _spec(ACCOUNT_ID, IssueRefundArgs),
    "update_prod_config": _spec(CONFIG_ID, UpdateProdConfigArgs),
}


@dataclass(frozen=True)
class Action:
    """A validated action. ``args`` holds exactly the declared fields."""

    tool: str
    resource_id: str | None
    args: dict[str, str]
    action_hash: str


def _describe(error: Any) -> str:
    # Unknown field names are attacker-controlled: they are never echoed.
    if error["type"] == "extra_forbidden":
        return "unknown field"
    field = ".".join(str(part) for part in error["loc"]) or "args"
    return f"{field}: {error['type']}"


def validate_action(tool: Any, resource_id: Any, args: Any) -> Action:
    """Validate one proposed action and compute its hash, or raise SchemaError.

    Error messages name the offending field and rule, never the submitted value.
    """
    if type(tool) is not str or tool not in TOOLS:
        raise SchemaError("unknown tool")
    spec = TOOLS[tool]

    if spec.resource is None:
        if resource_id is not None:
            raise SchemaError("resource_id must be null for this tool")
    elif type(resource_id) is not str or spec.resource.fullmatch(resource_id) is None:
        raise SchemaError("resource_id does not match the required format")

    if type(args) is not dict:
        raise SchemaError("args must be an object")
    try:
        validated = spec.args.model_validate(args).model_dump()
    except ValidationError as exc:
        details = "; ".join(sorted({_describe(error) for error in exc.errors()}))
        raise SchemaError(f"invalid args ({details})") from None
    except (TypeError, ValueError):
        raise SchemaError("invalid args") from None

    try:
        digest = action_hash(tool, resource_id, validated)
    except CanonError:
        raise SchemaError("action cannot be canonicalized") from None
    return Action(tool=tool, resource_id=resource_id, args=validated, action_hash=digest)
