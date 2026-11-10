"""Policy loader, policy hash and tier classification (threats T2, T9, T17)."""

import dataclasses
import hashlib
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from ullr_ai.gateway.policy import TOOL_TIERS, PolicyError, load_policy, tier_of
from ullr_ai.gateway.schemas import TOOLS

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"

BASE = """\
tools:
  read_document:
    tier: R0
  send_email:
    tier: R2
  delete_document:
    tier: R2
    on_tainted_session: require_approval
  issue_refund:
    tier: R2
    constraints:
      max_amount: "500.00"
      currency: [EUR]
    budgets:
      - key: [account_id]
        window: 24h
        max_total: "1000.00"
default: deny
approval:
  ttl_seconds: 300
  max_pending_per_session: 3
"""


def write(tmp_path, text):
    path = tmp_path / "policy.yaml"
    path.write_bytes(text.encode("utf-8"))
    return path


def variant(old, new):
    assert old in BASE
    return BASE.replace(old, new, 1)


# --- Default policy ----------------------------------------------------------


def test_default_policy_loads():
    policy = load_policy(DEFAULT_POLICY).policy
    assert policy.default == "deny"
    assert policy.approval.ttl_seconds == 300
    assert policy.approval.max_pending_per_session == 3
    assert set(policy.tools) == set(TOOLS)


def test_default_policy_matches_the_architecture_example():
    tools = load_policy(DEFAULT_POLICY).policy.tools
    refund = tools["issue_refund"]
    assert refund.constraints.max_amount == "500.00"
    assert refund.constraints.currency == ["EUR"]
    assert [(b.key, b.window, b.max_total) for b in refund.budgets] == [
        (["account_id"], "24h", "1000.00"),
        (["agent_id"], "24h", "600.00"),
    ]
    assert tools["delete_document"].on_tainted_session == "require_approval"


def test_default_policy_tiers_match_the_threat_model():
    tools = load_policy(DEFAULT_POLICY).policy.tools
    assert {name: tool.tier for name, tool in tools.items()} == TOOL_TIERS


# --- Policy hash -------------------------------------------------------------


def test_policy_hash_is_sha256_of_the_raw_bytes():
    loaded = load_policy(DEFAULT_POLICY)
    assert loaded.policy_hash == "sha256:" + hashlib.sha256(DEFAULT_POLICY.read_bytes()).hexdigest()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", loaded.policy_hash)


def test_policy_hash_is_stable_across_loads(tmp_path):
    path = write(tmp_path, BASE)
    assert load_policy(path).policy_hash == load_policy(path).policy_hash
    assert load_policy(str(path)).policy_hash == load_policy(path).policy_hash


@pytest.mark.parametrize(
    "changed",
    [
        BASE + "# comment\n",
        BASE + "\n",
        BASE.replace('"500.00"', '"500.01"'),
        BASE.replace("ttl_seconds: 300", "ttl_seconds: 301"),
        BASE.replace("\n", "\r\n"),
    ],
)
def test_any_byte_change_changes_the_policy_hash(tmp_path, changed):
    reference = load_policy(write(tmp_path, BASE)).policy_hash
    assert load_policy(write(tmp_path, changed)).policy_hash != reference


# --- Tier classification -----------------------------------------------------


def test_tier_table_is_the_threat_model_table():
    assert TOOL_TIERS == {
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


def test_every_tool_with_a_schema_has_a_tier_and_conversely():
    assert set(TOOL_TIERS) == set(TOOLS)


@pytest.mark.parametrize(("tool", "tier"), sorted(TOOL_TIERS.items()))
def test_tier_of_known_tools(tool, tier):
    assert tier_of(tool) == tier


@pytest.mark.parametrize(
    "tool",
    [
        "drop_database",
        "",
        "Send_Email",
        "SEND_EMAIL",
        "send-email",
        "send_email ",
        None,
        1,
        ["send_email"],
    ],
)
def test_tier_of_unknown_tool_raises(tool):
    with pytest.raises(PolicyError, match="unknown tool"):
        tier_of(tool)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("send_email:\n    tier: R2", "send_email:\n    tier: R1"),  # downgrade
        ("send_email:\n    tier: R2", "send_email:\n    tier: R0"),
        ("read_document:\n    tier: R0", "read_document:\n    tier: R2"),  # must be equal
        ("read_document:\n    tier: R0", "read_document:\n    tier: R3"),
        ("read_document:\n    tier: R0", "read_document:\n    tier: r0"),
        ("read_document:\n    tier: R0", "read_document:\n    tier: 0"),
        ("read_document:\n    tier: R0", "read_document: {}"),
    ],
)
def test_policy_cannot_reclassify_a_tool(tmp_path, old, new):
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, variant(old, new)))


# --- Rejected policies (fail closed) -----------------------------------------


def test_base_policy_is_valid(tmp_path):
    assert load_policy(write(tmp_path, BASE)).policy.default == "deny"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # default must be deny
        ("default: deny", "default: allow"),
        ("default: deny", "default: DENY"),
        ("default: deny", "default: null"),
        ("default: deny\n", ""),
        # unknown tools and fields
        ("  send_email:", "  send_mail:"),
        ("  send_email:", "  Send_Email:"),
        ("default: deny", "default: deny\nhot_reload: true"),
        ("    tier: R0", "    tier: R0\n    allow_without_approval: true"),
        ("  ttl_seconds: 300", "  ttl_seconds: 300\n  auto_approve: true"),
        # duplicate keys
        ("default: deny", "default: allow\ndefault: deny"),
        ("    tier: R0", "    tier: R0\n    tier: R0"),
        ("  send_email:\n    tier: R2", "  send_email:\n    tier: R2\n  send_email:\n    tier: R2"),
        # amounts must be canonical strings
        ('max_amount: "500.00"', "max_amount: 500.00"),
        ('max_amount: "500.00"', "max_amount: 500"),
        ('max_amount: "500.00"', 'max_amount: "500"'),
        ('max_amount: "500.00"', 'max_amount: "0500.00"'),
        ('max_total: "1000.00"', "max_total: 1000.00"),
        ('max_total: "1000.00"', 'max_total: "1,000.00"'),
        # currency
        ("currency: [EUR]", "currency: [XXX]"),
        ("currency: [EUR]", "currency: []"),
        ("currency: [EUR]", "currency: EUR"),
        # budgets
        ("window: 24h", "window: 24"),
        ("window: 24h", "window: 1d"),
        ("window: 24h", "window: 0h"),
        ("window: 24h", "window: 24H"),
        ("window: 24h", "window: 1000h"),
        ("key: [account_id]", "key: [session_id]"),
        ("key: [account_id]", "key: [account_id, agent_id]"),
        ("key: [account_id]", "key: []"),
        ("key: [account_id]", "key: account_id"),
        # taint escalation
        ("on_tainted_session: require_approval", "on_tainted_session: allow"),
        ("on_tainted_session: require_approval", "on_tainted_session: true"),
        # approval settings
        ("ttl_seconds: 300", 'ttl_seconds: "300"'),
        ("ttl_seconds: 300", "ttl_seconds: 300.0"),
        ("ttl_seconds: 300", "ttl_seconds: 0"),
        ("ttl_seconds: 300", "ttl_seconds: -1"),
        ("ttl_seconds: 300", "ttl_seconds: true"),
        ("ttl_seconds: 300", "ttl_seconds: 86401"),
        ("max_pending_per_session: 3", "max_pending_per_session: 0"),
        ("  max_pending_per_session: 3\n", ""),
        # constraints and budgets only apply to tools with an amount
        (
            "  send_email:\n    tier: R2",
            '  send_email:\n    tier: R2\n    constraints:\n      max_amount: "1.00"\n'
            "      currency: [EUR]",
        ),
        (
            "    on_tainted_session: require_approval",
            '    budgets:\n      - key: [agent_id]\n        window: 24h\n        max_total: "1.00"',
        ),
    ],
)
def test_invalid_policy_fails_the_load(tmp_path, old, new):
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, variant(old, new)))


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# only a comment\n",
        "null\n",
        "[]\n",
        "deny\n",
        "tools: {}\n",
        "tools: [\n",  # syntax error
        BASE + "---\n" + BASE,  # several documents
        BASE.replace("tools:", "tools: !!python/object/apply:os.getcwd []\nx:"),
    ],
)
def test_malformed_policy_file_fails_the_load(tmp_path, text):
    with pytest.raises(PolicyError):
        load_policy(write(tmp_path, text))


def test_non_utf8_policy_file_fails_the_load(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_bytes(BASE.encode("utf-8") + b"# \xff\n")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_missing_or_unreadable_policy_file_fails_the_load(tmp_path):
    with pytest.raises(PolicyError, match="cannot be read"):
        load_policy(tmp_path / "absent.yaml")
    with pytest.raises(PolicyError, match="cannot be read"):
        load_policy(tmp_path)  # a directory


def test_tool_absent_from_the_policy_is_simply_not_listed(tmp_path):
    policy = load_policy(write(tmp_path, BASE)).policy
    assert "update_prod_config" not in policy.tools
    assert policy.default == "deny"


def test_loaded_policy_is_immutable(tmp_path):
    loaded = load_policy(write(tmp_path, BASE))
    with pytest.raises(ValidationError, match="frozen"):
        loaded.policy.default = "allow"
    with pytest.raises(dataclasses.FrozenInstanceError):
        loaded.policy_hash = "sha256:0"
