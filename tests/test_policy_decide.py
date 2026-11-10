"""Deterministic policy decisions (T2, default deny, taint escalation)."""

import pytest

from conftest import DEFAULT_POLICY
from ullr_ai.gateway.policy import TOOL_TIERS, Decision, decide, load_policy
from ullr_ai.gateway.schemas import validate_action

EMAIL = {"to": "contact_1", "subject": "s", "body": "b"}
ACTIONS = {
    "read_document": ("doc_1", {}),
    "list_documents": (None, {}),
    "read_inbox": (None, {}),
    "get_balance": ("acct_1", {}),
    "draft_email": (None, EMAIL),
    "update_document": ("doc_1", {"content": "c"}),
    "send_email": (None, EMAIL),
    "delete_document": ("doc_1", {}),
    "issue_refund": ("acct_1", {"amount": "100.00", "currency": "EUR"}),
    "update_prod_config": ("cfg_1", {"value": "v"}),
}


def action(tool, **overrides):
    resource_id, args = ACTIONS[tool]
    return validate_action(tool, resource_id, {**args, **overrides})


@pytest.fixture(scope="module")
def policy():
    return load_policy(DEFAULT_POLICY).policy


def custom(tmp_path, old, new):
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    assert old in text
    path = tmp_path / "policy.yaml"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return load_policy(path).policy


@pytest.mark.parametrize("tool", sorted(ACTIONS))
@pytest.mark.parametrize("tainted", [False, True])
def test_default_policy_decision_follows_the_tier(policy, tool, tainted):
    decision = decide(policy, action(tool), tainted=tainted)
    if TOOL_TIERS[tool] == "R2":
        assert decision == Decision("REQUIRE_APPROVAL", "irreversible_action")
    else:
        assert decision == Decision("ALLOW", "within_policy")


@pytest.mark.parametrize("tool", [name for name, tier in TOOL_TIERS.items() if tier == "R2"])
def test_an_irreversible_action_is_never_allowed(policy, tool):
    for tainted in (False, True):
        assert decide(policy, action(tool), tainted=tainted).outcome != "ALLOW"


@pytest.mark.parametrize(
    ("amount", "outcome"),
    [
        ("0.01", "REQUIRE_APPROVAL"),
        ("499.99", "REQUIRE_APPROVAL"),
        ("500.00", "REQUIRE_APPROVAL"),
        ("500.01", "DENY"),
        ("900.00", "DENY"),
        ("9999999.99", "DENY"),
    ],
)
def test_refund_amount_limit(policy, amount, outcome):
    decision = decide(policy, action("issue_refund", amount=amount), tainted=False)
    assert decision.outcome == outcome
    if outcome == "DENY":
        assert decision.reason == "amount_over_limit"


@pytest.mark.parametrize("currency", ["USD", "GBP"])
def test_refund_currency_not_allowed_by_the_policy(policy, currency):
    decision = decide(policy, action("issue_refund", currency=currency), tainted=False)
    assert decision == Decision("DENY", "currency_not_allowed")


@pytest.mark.parametrize("tool", sorted(ACTIONS))
def test_tool_absent_from_the_policy_is_denied(tmp_path, tool):
    text = "tools: {}\ndefault: deny\napproval:\n  ttl_seconds: 300\n  max_pending_per_session: 3\n"
    path = tmp_path / "empty.yaml"
    path.write_text(text, encoding="utf-8")
    empty = load_policy(path).policy
    for tainted in (False, True):
        assert decide(empty, action(tool), tainted=tainted) == Decision(
            "DENY", "tool_not_in_policy"
        )


def test_tainted_session_can_be_denied(tmp_path):
    policy = custom(
        tmp_path,
        "  update_document:\n    tier: R1\n",
        "  update_document:\n    tier: R1\n    on_tainted_session: deny\n",
    )
    assert decide(policy, action("update_document"), tainted=False).outcome == "ALLOW"
    assert decide(policy, action("update_document"), tainted=True) == Decision(
        "DENY", "tainted_session"
    )


def test_tainted_session_can_escalate_a_reversible_action(tmp_path):
    policy = custom(
        tmp_path,
        "  update_document:\n    tier: R1\n",
        "  update_document:\n    tier: R1\n    on_tainted_session: require_approval\n",
    )
    assert decide(policy, action("update_document"), tainted=False).outcome == "ALLOW"
    assert decide(policy, action("update_document"), tainted=True) == Decision(
        "REQUIRE_APPROVAL", "tainted_session"
    )


def test_taint_denial_takes_precedence_over_approval_for_r2(tmp_path):
    policy = custom(tmp_path, "on_tainted_session: require_approval", "on_tainted_session: deny")
    assert decide(policy, action("delete_document"), tainted=False).outcome == "REQUIRE_APPROVAL"
    assert decide(policy, action("delete_document"), tainted=True) == Decision(
        "DENY", "tainted_session"
    )


def test_constraints_are_checked_before_anything_else(tmp_path):
    policy = custom(
        tmp_path,
        "  issue_refund:\n    tier: R2\n",
        "  issue_refund:\n    tier: R2\n    on_tainted_session: deny\n",
    )
    over = action("issue_refund", amount="900.00")
    assert decide(policy, over, tainted=True) == Decision("DENY", "amount_over_limit")
