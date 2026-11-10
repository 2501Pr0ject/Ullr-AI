"""Policy loading, policy hash and tier classification (ARCHITECTURE.md section 5).

The policy is read once at start-up. Any defect in the file fails the load:
the Gateway must not start on a policy it does not fully understand.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from ullr_ai.gateway.schemas import (
    TOOLS,
    Action,
    Amount,
    Currency,
    StrictModel,
    amount_to_cents,
    full_match,
)

Tier = Literal["R0", "R1", "R2"]

# Reversibility tiers from THREAT_MODEL.md section 1. The policy file must
# state the same tier for every tool it lists: it cannot reclassify a tool.
TOOL_TIERS: dict[str, Tier] = {
    "read_document": "R0",
    "list_documents": "R0",
    "read_inbox": "R0",
    "get_balance": "R0",
    "draft_email": "R1",
    "update_document": "R1",
    "send_email": "R2",
    "delete_document": "R2",
    "issue_refund": "R2",
    "update_prod_config": "R2",
}


class PolicyError(ValueError):
    """The policy cannot be loaded or a tool is unknown."""


class Constraints(StrictModel):
    max_amount: Amount
    currency: Annotated[list[Currency], Field(min_length=1)]


class Budget(StrictModel):
    key: Annotated[list[Literal["account_id", "agent_id"]], Field(min_length=1, max_length=1)]
    window: Annotated[str, full_match(r"[1-9][0-9]{0,2}h")]
    max_total: Amount


class ToolPolicy(StrictModel):
    tier: Tier
    constraints: Constraints | None = None
    budgets: list[Budget] = Field(default_factory=list)
    on_tainted_session: Literal["require_approval", "deny"] | None = None


class ApprovalPolicy(StrictModel):
    ttl_seconds: Annotated[int, Field(ge=1, le=86_400)]
    max_pending_per_session: Annotated[int, Field(ge=1, le=100)]


class Policy(StrictModel):
    tools: dict[str, ToolPolicy]
    default: Literal["deny"]
    approval: ApprovalPolicy

    @model_validator(mode="after")
    def _check_tools(self) -> "Policy":
        for name, tool in self.tools.items():
            if name not in TOOL_TIERS:
                raise ValueError("policy lists an unknown tool")
            if tool.tier != TOOL_TIERS[name]:
                raise ValueError(f"tier of {name} must be {TOOL_TIERS[name]}")
            has_amount = "amount" in TOOLS[name].args.model_fields
            if (tool.constraints is not None or tool.budgets) and not has_amount:
                raise ValueError(f"{name} has no amount: constraints and budgets do not apply")
        return self


@dataclass(frozen=True)
class LoadedPolicy:
    policy: Policy
    policy_hash: str


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
            except TypeError:
                raise yaml.constructor.ConstructorError(
                    None, None, "unhashable mapping key", key_node.start_mark
                ) from None
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate mapping key", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_policy(path: Path | str) -> LoadedPolicy:
    """Load and validate the policy file. The hash covers the raw file bytes."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise PolicyError("policy file cannot be read") from None
    try:
        # A SafeLoader subclass: no arbitrary object construction.
        data = yaml.load(raw.decode("utf-8", errors="strict"), Loader=_UniqueKeyLoader)  # noqa: S506
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyError(f"policy file is not valid YAML: {exc}") from None
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"policy file is invalid: {exc}") from None
    except RecursionError:
        raise PolicyError("policy file is invalid") from None
    return LoadedPolicy(policy=policy, policy_hash="sha256:" + hashlib.sha256(raw).hexdigest())


def tier_of(tool: Any) -> Tier:
    """Tier of a canonical tool name. Unknown names raise: there is no default tier."""
    if type(tool) is not str or tool not in TOOL_TIERS:
        raise PolicyError("unknown tool")
    return TOOL_TIERS[tool]


Outcome = Literal["DENY", "ALLOW", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str


def decide(policy: Policy, action: Action, *, tainted: bool) -> Decision:
    """Deterministic decision for one validated action. No model is consulted.

    Order: default deny, hard constraints, taint denial, then the tier.
    An R2 action is never ALLOW.
    """
    tool = policy.tools.get(action.tool)
    if tool is None:
        return Decision("DENY", "tool_not_in_policy")
    if tool.constraints is not None:
        if action.args["currency"] not in tool.constraints.currency:
            return Decision("DENY", "currency_not_allowed")
        limit = amount_to_cents(tool.constraints.max_amount)
        if amount_to_cents(action.args["amount"]) > limit:
            return Decision("DENY", "amount_over_limit")
    if tainted and tool.on_tainted_session == "deny":
        return Decision("DENY", "tainted_session")
    if TOOL_TIERS[action.tool] == "R2":
        return Decision("REQUIRE_APPROVAL", "irreversible_action")
    if tainted and tool.on_tainted_session == "require_approval":
        return Decision("REQUIRE_APPROVAL", "tainted_session")
    return Decision("ALLOW", "within_policy")
