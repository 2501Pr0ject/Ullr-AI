"""Tool allow-list and per-tool schemas (threats T9 and T10)."""

import dataclasses
import re
from decimal import Decimal

import pytest

from ullr_ai.gateway.canon import CanonError, action_hash, parse_json_strict
from ullr_ai.gateway.schemas import TOOLS, Action, SchemaError, validate_action

EMAIL = {"to": "contact_7", "subject": "Quarterly report", "body": "Hello,\nSee attached.\n"}

# One valid (resource_id, args) per tool.
VALID = {
    "read_document": ("doc_1", {}),
    "list_documents": (None, {}),
    "read_inbox": (None, {}),
    "get_balance": ("acct_1", {}),
    "draft_email": (None, EMAIL),
    "update_document": ("doc_1", {"content": "New content\nSecond line"}),
    "send_email": (None, EMAIL),
    "delete_document": ("doc_1", {}),
    "issue_refund": ("acct_1", {"amount": "100.00", "currency": "EUR"}),
    "update_prod_config": ("cfg_1", {"value": "enabled"}),
}

DOCUMENT_TOOLS = ["read_document", "update_document", "delete_document"]
NO_RESOURCE_TOOLS = ["list_documents", "read_inbox", "draft_email", "send_email"]

# (tool, field, max length, multiline)
TEXT_FIELDS = [
    ("send_email", "subject", 200, False),
    ("send_email", "body", 20_000, True),
    ("draft_email", "subject", 200, False),
    ("draft_email", "body", 20_000, True),
    ("update_document", "content", 20_000, True),
    ("update_prod_config", "value", 2_000, False),
]


def rejected(tool, resource_id, args):
    with pytest.raises(SchemaError):
        validate_action(tool, resource_id, args)


def with_field(tool, field, value):
    resource_id, args = VALID[tool]
    return tool, resource_id, {**args, field: value}


def refund(amount="100.00", currency="EUR"):
    return validate_action("issue_refund", "acct_1", {"amount": amount, "currency": currency})


# --- Tool name (T9) ----------------------------------------------------------


def test_allow_list_is_exactly_the_ten_reference_tools():
    assert set(TOOLS) == set(VALID)
    assert len(TOOLS) == 10


@pytest.mark.parametrize("tool", sorted(VALID))
def test_each_canonical_tool_accepted(tool):
    resource_id, args = VALID[tool]
    action = validate_action(tool, resource_id, args)
    assert action == Action(tool, resource_id, args, action_hash(tool, resource_id, args))
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", action.action_hash)


@pytest.mark.parametrize(
    "tool",
    [
        "drop_database",
        "",
        "execute",
        # case variants
        "Send_Email",
        "SEND_EMAIL",
        "sendEmail",
        "Delete_document",
        # aliases
        "send-email",
        "sendemail",
        "email.send",
        "delete_doc",
        "send_email_v2",
        "tools.send_email",
        # padding and decoration
        " send_email",
        "send_email ",
        "send_email\n",
        "send_email\x00",
        "send_email\u200b",
        "\ufeffsend_email",
        # homoglyphs
        "s\u0435nd_email",  # Cyrillic small ie
        "\uff53end_email",  # fullwidth s
        "send\uff3femail",  # fullwidth low line
    ],
)
def test_unknown_alias_and_variant_tool_names_rejected(tool):
    with pytest.raises(SchemaError, match="unknown tool"):
        validate_action(tool, None, EMAIL)


@pytest.mark.parametrize(
    "tool", [None, 1, True, ["send_email"], {"name": "send_email"}, b"send_email"]
)
def test_non_string_tool_rejected(tool):
    with pytest.raises(SchemaError, match="unknown tool"):
        validate_action(tool, None, EMAIL)


# --- Resource identifiers (T10) ----------------------------------------------


@pytest.mark.parametrize("resource_id", ["doc_0", "doc_1", "doc_007", "doc_12345678"])
def test_document_ids_accepted(resource_id):
    assert validate_action("delete_document", resource_id, {}).resource_id == resource_id


@pytest.mark.parametrize(
    "resource_id",
    [
        # path syntax
        "./doc_1",
        "../doc_1",
        "/doc_1",
        "doc_1/",
        "docs/doc_1",
        "doc_1/../doc_2",
        "doc_1\\",
        # malformed
        "",
        "doc_",
        "doc_123456789",
        "doc_-1",
        "doc_+1",
        "doc_1.0",
        "doc_0x1",
        "doc_1e2",
        "doc_a",
        "doc1",
        "doc-1",
        "DOC_1",
        "Doc_1",
        " doc_1",
        "doc_1 ",
        "doc_1\n",
        "doc_1\x00",
        "doc_1,doc_2",
        "doc_*",
        "doc_%31",
        "doc_\uff11",  # fullwidth digit
        "doc_\u0663",  # Arabic-Indic digit
        "doc_1\u200b",
        "d\u043ec_1",  # Cyrillic o
    ],
)
@pytest.mark.parametrize("tool", DOCUMENT_TOOLS)
def test_non_canonical_document_ids_rejected(tool, resource_id):
    rejected(tool, resource_id, VALID[tool][1])


@pytest.mark.parametrize("resource_id", [None, 1, 1.0, True, ["doc_1"], {"id": "doc_1"}, b"doc_1"])
@pytest.mark.parametrize(
    "tool", [*DOCUMENT_TOOLS, "get_balance", "issue_refund", "update_prod_config"]
)
def test_non_string_resource_id_rejected_where_required(tool, resource_id):
    rejected(tool, resource_id, VALID[tool][1])


@pytest.mark.parametrize(
    ("tool", "resource_id"),
    [
        ("delete_document", "acct_1"),
        ("delete_document", "cfg_1"),
        ("delete_document", "contact_1"),
        ("read_document", "acct_1"),
        ("update_document", "cfg_1"),
        ("get_balance", "doc_1"),
        ("issue_refund", "doc_1"),
        ("issue_refund", "contact_1"),
        ("update_prod_config", "doc_1"),
        ("update_prod_config", "acct_1"),
    ],
)
def test_wrong_kind_of_resource_rejected(tool, resource_id):
    rejected(tool, resource_id, VALID[tool][1])


@pytest.mark.parametrize("resource_id", ["acct_1", "acct_12345678"])
def test_account_ids_accepted(resource_id):
    assert validate_action("get_balance", resource_id, {}).resource_id == resource_id


@pytest.mark.parametrize(
    "resource_id", ["acct_", "acct_123456789", "ACCT_1", "account_1", "./acct_1"]
)
def test_non_canonical_account_ids_rejected(resource_id):
    rejected("get_balance", resource_id, {})
    rejected("issue_refund", resource_id, VALID["issue_refund"][1])


@pytest.mark.parametrize(
    "resource_id", ["cfg_", "cfg_123456789", "CFG_1", "rate_limit", "../cfg_1"]
)
def test_non_canonical_config_ids_rejected(resource_id):
    rejected("update_prod_config", resource_id, {"value": "enabled"})


@pytest.mark.parametrize("resource_id", ["", "null", "none", "doc_1", "inbox", 0, False, [], {}])
@pytest.mark.parametrize("tool", NO_RESOURCE_TOOLS)
def test_tools_without_resource_require_null(tool, resource_id):
    rejected(tool, resource_id, VALID[tool][1])


@pytest.mark.parametrize(
    "to",
    [
        "a@example.com",
        "contact_7 ",
        " contact_7",
        "contact_7\n",
        "contact_",
        "contact_123456789",
        "Contact_7",
        "contact_7,contact_8",
        "",
        ["contact_7"],
        7,
        None,
    ],
)
@pytest.mark.parametrize("tool", ["send_email", "draft_email"])
def test_recipient_must_be_one_contact_id(tool, to):
    rejected(*with_field(tool, "to", to))


# --- Amounts and currency (T10) ----------------------------------------------


@pytest.mark.parametrize("amount", ["0.01", "0.10", "1.00", "100.00", "400.00", "9999999.99"])
def test_canonical_amounts_accepted(amount):
    assert refund(amount=amount).args["amount"] == amount


@pytest.mark.parametrize(
    "amount", [100, 100.0, 100.5, True, None, Decimal("100.00"), ["100.00"], b"100.00"]
)
def test_non_string_amounts_rejected_without_coercion(amount):
    with pytest.raises(SchemaError):
        refund(amount=amount)


@pytest.mark.parametrize(
    "amount",
    [
        "",
        "100",
        "100.0",
        "100.000",
        ".50",
        "100.",
        "1e2",
        "1E2",
        "+100.00",
        "-100.00",
        "100,00",
        "1,000.00",
        "1 000.00",
        " 100.00",
        "100.00 ",
        "100.00\n",
        "100.00\x00",
        "100.00 EUR",
        "0x64.00",
        "10000000.00",
        "NaN",
        "Infinity",
        "\uff11\uff10\uff10.00",  # fullwidth digits
        "\u0661\u0660\u0660.00",  # Arabic-Indic digits
        "100\uff0e00",  # fullwidth full stop
        "100.00\u200b",
    ],
)
def test_non_canonical_amount_strings_rejected(amount):
    with pytest.raises(SchemaError):
        refund(amount=amount)


@pytest.mark.parametrize("amount", ["0100.00", "00.50", "00.00", "01.00", "0.00"])
def test_leading_zeros_and_zero_amount_rejected(amount):
    with pytest.raises(SchemaError):
        refund(amount=amount)


@pytest.mark.parametrize("currency", ["EUR", "USD", "GBP"])
def test_allowed_currencies_accepted(currency):
    assert refund(currency=currency).args["currency"] == currency


@pytest.mark.parametrize(
    "currency",
    [
        "eur",
        "Eur",
        "EURO",
        "EU",
        "",
        "\u20ac",
        "XXX",
        "JPY",
        "EUR ",
        " EUR",
        "EUR\n",
        None,
        978,
        ["EUR"],
    ],
)
def test_unknown_currencies_rejected(currency):
    with pytest.raises(SchemaError):
        refund(currency=currency)


# --- Structure (T10) ---------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(VALID))
def test_unknown_field_rejected_on_every_tool(tool):
    rejected(*with_field(tool, "extra", "x"))
    rejected(*with_field(tool, "", "x"))


@pytest.mark.parametrize(
    ("tool", "field"),
    [(tool, field) for tool, (_, args) in sorted(VALID.items()) for field in args],
)
def test_each_required_field_is_mandatory(tool, field):
    resource_id, args = VALID[tool]
    remaining = {key: value for key, value in args.items() if key != field}
    rejected(tool, resource_id, remaining)


@pytest.mark.parametrize("args", [None, [], "{}", 0, False, [("amount", "1.00")], b"{}"])
@pytest.mark.parametrize("tool", sorted(VALID))
def test_args_must_be_an_object(tool, args):
    rejected(tool, VALID[tool][0], args)


@pytest.mark.parametrize("value", [1, 1.5, True, None, b"text", ["text"], {"text": "x"}])
@pytest.mark.parametrize(("tool", "field"), [(tool, field) for tool, field, _, _ in TEXT_FIELDS])
def test_text_fields_are_not_coerced(tool, field, value):
    rejected(*with_field(tool, field, value))


@pytest.mark.parametrize(
    "field", ["provenance", "trusted", "approved", "tier", "agent_id", "session_id"]
)
@pytest.mark.parametrize("tool", ["delete_document", "issue_refund", "send_email"])
def test_agent_supplied_control_fields_rejected(tool, field):
    rejected(*with_field(tool, field, "internal"))


def test_field_names_are_exact():
    rejected("issue_refund", "acct_1", {"Amount": "100.00", "currency": "EUR"})
    rejected("issue_refund", "acct_1", {"amount ": "100.00", "currency": "EUR"})
    rejected("issue_refund", "acct_1", {"amount": "100.00", "currency": "EUR", "AMOUNT": "9.00"})


# --- Free-text fields --------------------------------------------------------


@pytest.mark.parametrize(("tool", "field", "max_length", "_multiline"), TEXT_FIELDS)
def test_text_length_bounds(tool, field, max_length, _multiline):
    rejected(*with_field(tool, field, ""))
    assert validate_action(*with_field(tool, field, "x")).args[field] == "x"
    assert (
        len(validate_action(*with_field(tool, field, "x" * max_length)).args[field]) == max_length
    )
    rejected(*with_field(tool, field, "x" * (max_length + 1)))


@pytest.mark.parametrize(
    "text",
    [
        "cafe\u0301",  # not NFC
        "a\x00b",
        "a\tb",
        "a\rb",
        "a\r\nb",
        "a\x1bb",
        "a\x7fb",
        "a\u200bb",  # zero width space
        "a\u202eb",  # right-to-left override
        "a\u2066b",  # left-to-right isolate
        "a\ufeffb",
        "a\u2028b",  # line separator
        "a\ue000b",  # private use
        "a\ud800b",  # lone surrogate
    ],
)
@pytest.mark.parametrize(("tool", "field"), [(tool, field) for tool, field, _, _ in TEXT_FIELDS])
def test_non_canonical_text_rejected_on_every_field(tool, field, text):
    rejected(*with_field(tool, field, text))


@pytest.mark.parametrize(("tool", "field", "_max_length", "multiline"), TEXT_FIELDS)
def test_line_feed_only_in_multiline_fields(tool, field, _max_length, multiline):
    candidate = with_field(tool, field, "first\nsecond")
    if multiline:
        assert validate_action(*candidate).args[field] == "first\nsecond"
    else:
        rejected(*candidate)


def test_text_is_kept_byte_exact():
    plain = validate_action(*with_field("send_email", "body", "hello"))
    padded = validate_action(*with_field("send_email", "body", " hello "))
    assert padded.args["body"] == " hello "
    assert plain.action_hash != padded.action_hash


def test_non_ascii_text_accepted():
    text = "R\u00e9sum\u00e9 \u65e5\u672c\u8a9e"
    assert validate_action(*with_field("send_email", "subject", text)).args["subject"] == text


# --- End to end --------------------------------------------------------------


def test_action_hashes_are_stable_and_distinct_per_tool():
    hashes = {tool: validate_action(tool, *VALID[tool]).action_hash for tool in VALID}
    again = {tool: validate_action(tool, *VALID[tool]).action_hash for tool in VALID}
    assert hashes == again
    assert len(set(hashes.values())) == len(VALID)


def test_hash_does_not_depend_on_argument_order():
    first = validate_action("issue_refund", "acct_1", {"amount": "100.00", "currency": "EUR"})
    second = validate_action("issue_refund", "acct_1", {"currency": "EUR", "amount": "100.00"})
    assert first.action_hash == second.action_hash


def test_approving_one_document_does_not_cover_another():
    assert (
        validate_action("delete_document", "doc_1", {}).action_hash
        != validate_action("delete_document", "doc_2", {}).action_hash
    )


def test_duplicate_key_is_rejected_before_the_schema_sees_it():
    body = (
        b'{"tool":"issue_refund","resource_id":"acct_1",'
        b'"args":{"amount":"100.00","amount":"900.00","currency":"EUR"}}'
    )
    with pytest.raises(CanonError, match="duplicate key"):
        parse_json_strict(body)


def test_float_amount_is_rejected_at_parse_time():
    body = (
        b'{"tool":"issue_refund","resource_id":"acct_1","args":{"amount":100.00,"currency":"EUR"}}'
    )
    with pytest.raises(CanonError, match="floats"):
        parse_json_strict(body)


def test_valid_request_bytes_to_action():
    body = (
        b'{"tool":"issue_refund","resource_id":"acct_1",'
        b'"args":{"currency":"EUR","amount":"100.00"}}'
    )
    request = parse_json_strict(body)
    action = validate_action(request["tool"], request["resource_id"], request["args"])
    assert action.action_hash == (
        "sha256:77ecbf1c5826d274f4b80a2a1be7a80b031f11cb1af8ebe7912732d3c808fa38"
    )


def test_integer_amount_survives_parsing_but_not_the_schema():
    request = parse_json_strict(b'{"amount":100,"currency":"EUR"}')
    rejected("issue_refund", "acct_1", request)


def test_action_is_immutable():
    action = validate_action("delete_document", "doc_1", {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.resource_id = "doc_2"


def test_returned_args_are_a_copy_of_the_validated_fields():
    args = {"amount": "100.00", "currency": "EUR"}
    action = validate_action("issue_refund", "acct_1", args)
    args["amount"] = "900.00"
    assert action.args == {"amount": "100.00", "currency": "EUR"}


def test_error_messages_do_not_echo_submitted_values():
    marker = "MARKER-7f3a"
    with pytest.raises(SchemaError) as excinfo:
        validate_action("send_email", None, {**EMAIL, "body": marker + "\x00", marker: marker})
    assert marker not in str(excinfo.value)
