"""Canon v1 conformance (ARCHITECTURE.md section 4, threats T4 and T10)."""

import hashlib
import re
import unicodedata
from decimal import Decimal

import pytest

from ullr_ai.gateway import canon
from ullr_ai.gateway.canon import (
    MAX_BYTES,
    MAX_DEPTH,
    MAX_INT,
    CanonError,
    action_hash,
    canonical_json,
    check_text,
    parse_json_strict,
)

# --- Strict parsing: rejected ------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b'{"o":{"a":1,"a":2}}',
        b'[{"a":1,"a":2}]',
        b'{"a":1,"b":2,"a":3}',
        b'{"a":1,"a":1}',  # identical values are still a duplicate
        b'{"a":1,"\\u0061":2}',  # same key once unescaped
    ],
)
def test_duplicate_keys_rejected(data):
    with pytest.raises(CanonError, match="duplicate key"):
        parse_json_strict(data)


@pytest.mark.parametrize(
    "data",
    [b"NaN", b"Infinity", b"-Infinity", b'{"a":NaN}', b'{"a":Infinity}', b"[-Infinity]"],
)
def test_nan_and_infinity_rejected(data):
    with pytest.raises(CanonError):
        parse_json_strict(data)


@pytest.mark.parametrize(
    "token", [b"1.0", b"100.00", b"1e2", b"1E-2", b"0.1", b"-1.5", b"-0.0", b"1e400"]
)
def test_floats_rejected_everywhere(token):
    for data in (token, b'{"amount":' + token + b"}", b"[" + token + b"]"):
        with pytest.raises(CanonError, match="floats"):
            parse_json_strict(data)


@pytest.mark.parametrize("data", [b"-0", b'{"a":-0}', b"[-0]"])
def test_negative_zero_rejected(data):
    with pytest.raises(CanonError):
        parse_json_strict(data)


@pytest.mark.parametrize(
    "token",
    [
        str(MAX_INT + 1).encode(),
        str(-MAX_INT - 1).encode(),
        b"1" * 18,
        b"1" * 5000,  # beyond the interpreter's int conversion limit
    ],
)
def test_out_of_range_integers_rejected(token):
    with pytest.raises(CanonError, match="out of range"):
        parse_json_strict(b'{"a":' + token + b"}")


def test_integer_bounds_accepted():
    assert parse_json_strict(str(MAX_INT).encode()) == MAX_INT
    assert parse_json_strict(str(-MAX_INT).encode()) == -MAX_INT
    assert parse_json_strict(b"0") == 0


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":"\xff"}',  # invalid byte
        b'{"a":"\xc0\xaf"}',  # overlong encoding of "/"
        b'{"a":"\xed\xa0\x80"}',  # UTF-8 encoded surrogate
        b'{"a":"\xe2\x82"}',  # truncated sequence
        b"\xef\xbb\xbf{}",  # byte order mark
    ],
)
def test_invalid_utf8_and_bom_rejected(data):
    with pytest.raises(CanonError):
        parse_json_strict(data)


@pytest.mark.parametrize(
    "encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]
)
def test_other_unicode_encodings_rejected(encoding):
    with pytest.raises(CanonError):
        parse_json_strict('{"a":1}'.encode(encoding))


@pytest.mark.parametrize(
    "data",
    [
        rb'{"a":"\ud800"}',
        rb'{"a":"\udc00"}',
        rb'{"a":"\udc00\ud800"}',  # reversed pair
        rb'{"\ud800":1}',  # in a key
        rb'["x\udfffy"]',
    ],
)
def test_lone_surrogate_escapes_rejected(data):
    with pytest.raises(CanonError, match="surrogate"):
        parse_json_strict(data)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"  \n",
        b"{} {}",
        b"{}x",
        b'{"a":1}{"a":2}',
        b'{"a":1,}',
        b"[1,]",
        b'{"a":1}//c',
        b"/*c*/{}",
        b"{'a':1}",
        b"{a:1}",
        b'{"a":01}',
        b'{"a":+1}',
        b'{"a":0x10}',
        b'{"a":"x\ny"}',  # raw control character inside a string
        b'{"a":"x\x00y"}',
        b'{"a":1',
        b"True",
        b"None",
    ],
)
def test_malformed_json_rejected(data):
    with pytest.raises(CanonError):
        parse_json_strict(data)


def test_nesting_limit():
    assert parse_json_strict(b"[" * MAX_DEPTH + b"]" * MAX_DEPTH) is not None
    with pytest.raises(CanonError, match="too deep"):
        parse_json_strict(b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1))
    with pytest.raises(CanonError, match="too deep"):
        parse_json_strict(b'{"a":' * (MAX_DEPTH + 1) + b"1" + b"}" * (MAX_DEPTH + 1))


def test_extreme_nesting_is_a_clean_rejection():
    depth = 100_000
    with pytest.raises(CanonError):
        parse_json_strict(b"[" * depth + b"]" * depth)


def test_size_limit():
    padding = b'"' + b"a" * (MAX_BYTES - 2) + b'"'
    assert len(padding) == MAX_BYTES
    assert parse_json_strict(padding) == "a" * (MAX_BYTES - 2)
    with pytest.raises(CanonError, match="too large"):
        parse_json_strict(b'"' + b"a" * (MAX_BYTES - 1) + b'"')


@pytest.mark.parametrize("data", ['{"a":1}', bytearray(b"{}"), memoryview(b"{}"), None, 1])
def test_non_bytes_input_rejected(data):
    with pytest.raises(CanonError, match="bytes"):
        parse_json_strict(data)


# --- Strict parsing: accepted ------------------------------------------------


def test_valid_document_accepted():
    data = b'{"s":"x","i":42,"n":-7,"t":true,"f":false,"z":null,"l":[1,[2,{"k":"v"}]],"o":{}}'
    assert parse_json_strict(data) == {
        "s": "x",
        "i": 42,
        "n": -7,
        "t": True,
        "f": False,
        "z": None,
        "l": [1, [2, {"k": "v"}]],
        "o": {},
    }


def test_surrogate_pair_escape_decodes_to_one_code_point():
    assert parse_json_strict(rb'"\ud83d\ude00"') == "\U0001f600"


def test_input_whitespace_accepted_and_absent_from_canonical_output():
    value = parse_json_strict(b' { "b" : [ 1 , 2 ] ,\n\t"a" : null } \r\n')
    assert canonical_json(value) == b'{"a":null,"b":[1,2]}'


# --- Canonical encoding ------------------------------------------------------


def test_keys_sorted_at_every_depth():
    first = {"b": {"z": 1, "a": 2}, "a": [{"y": 1, "x": 2}]}
    second = {"a": [{"x": 2, "y": 1}], "b": {"a": 2, "z": 1}}
    expected = b'{"a":[{"x":2,"y":1}],"b":{"a":2,"z":1}}'
    assert canonical_json(first) == expected
    assert canonical_json(second) == expected


def test_no_insignificant_whitespace():
    assert canonical_json({"a": [1, 2], "b": {"c": "d e"}}) == b'{"a":[1,2],"b":{"c":"d e"}}'


def test_non_ascii_is_raw_utf8_and_keys_sort_by_code_point():
    # U+FF5E sorts before U+10000 by code point; UTF-16 code unit order is the opposite.
    value = {"\U00010000": 2, "\uff5e": 1, "\u00e9": 0}
    assert canonical_json(value) == (b'{"\xc3\xa9":0,"\xef\xbd\x9e":1,"\xf0\x90\x80\x80":2}')


def test_uppercase_sorts_before_lowercase():
    assert canonical_json({"a": 1, "B": 2, "_": 3}) == b'{"B":2,"_":3,"a":1}'


def test_string_escaping_golden_vector():
    value = '"\\\x00\x1f\n\r\t\b\f\x7f/\u00e9'
    assert canonical_json(value) == b'"\\"\\\\\\u0000\\u001f\\n\\r\\t\\b\\f\x7f/\xc3\xa9"'


def test_array_order_preserved():
    assert canonical_json([3, 1, 2]) == b"[3,1,2]"
    assert canonical_json([3, 1, 2]) != canonical_json([1, 2, 3])


def test_scalars_are_not_conflated():
    assert canonical_json(True) == b"true"
    assert canonical_json(False) == b"false"
    assert canonical_json(1) == b"1"
    assert canonical_json(0) == b"0"
    assert canonical_json(None) == b"null"
    assert canonical_json("1") == b'"1"'
    assert canonical_json("") == b'""'


class _StrSubclass(str):
    pass


class _IntSubclass(int):
    pass


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        float("nan"),
        float("inf"),
        Decimal("1.00"),
        b"x",
        (1, 2),
        {1, 2},
        {1: "a"},
        {None: "a"},
        {"a": 1.5},
        [{"a": [object()]}],
        MAX_INT + 1,
        -MAX_INT - 1,
        "\ud800",
        {"\ud800": 1},
        _StrSubclass("x"),
        _IntSubclass(1),
    ],
)
def test_encoder_rejects_everything_outside_the_data_model(value):
    with pytest.raises(CanonError):
        canonical_json(value)


def test_encoder_rejects_excessive_nesting():
    value: list = []
    for _ in range(MAX_DEPTH):
        value = [value]
    with pytest.raises(CanonError, match="too deep"):
        canonical_json(value)


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        "",
        0,
        None,
        True,
        {"a": {"b": [1, "x", None, False, {"c": []}]}},
        {"text": 'quote " backslash \\ newline \n tab \t'},
        {"\u00e9": "\U0001f600", "z": MAX_INT, "y": -MAX_INT},
    ],
)
def test_round_trip_and_idempotence(value):
    encoded = canonical_json(value)
    assert parse_json_strict(encoded) == value
    assert canonical_json(parse_json_strict(encoded)) == encoded


# --- Free text ---------------------------------------------------------------


def test_unicode_database_version_is_pinned():
    assert canon.UNICODE_VERSION == "15.0.0"
    assert unicodedata.unidata_version == canon.UNICODE_VERSION


@pytest.mark.parametrize(
    "text", ["", "hello", "caf\u00e9", "\u65e5\u672c\u8a9e", "a b  c", "x" * 1000]
)
def test_nfc_text_accepted_unchanged(text):
    assert check_text(text) is text


@pytest.mark.parametrize(
    "text",
    [
        "cafe\u0301",  # NFD of U+00E9
        "A\u030a",  # composes to U+00C5
        "\u212b",  # ANGSTROM SIGN, singleton decomposition
        "\u1100\u1161",  # Hangul jamo sequence
    ],
)
def test_non_nfc_text_rejected_not_normalized(text):
    with pytest.raises(CanonError, match="NFC"):
        check_text(text)


def test_compatibility_forms_are_left_alone_and_stay_distinct():
    fullwidth_a = "\uff21"
    ligature_fi = "\ufb01"
    assert check_text(fullwidth_a) == fullwidth_a
    assert check_text(ligature_fi) == ligature_fi
    assert canonical_json(fullwidth_a) != canonical_json("A")
    assert canonical_json(ligature_fi) != canonical_json("fi")


@pytest.mark.parametrize("char", ["\x00", "\t", "\r", "\x1b", "\x1f", "\x7f", "\x85", "\x9f"])
def test_control_characters_rejected(char):
    for multiline in (False, True):
        with pytest.raises(CanonError, match="forbidden character"):
            check_text(f"a{char}b", multiline=multiline)


def test_line_feed_only_in_multiline_fields():
    assert check_text("a\nb\n", multiline=True) == "a\nb\n"
    with pytest.raises(CanonError):
        check_text("a\nb")
    with pytest.raises(CanonError):
        check_text("a\r\nb", multiline=True)


@pytest.mark.parametrize(
    "char",
    [
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u200e",  # left-to-right mark
        "\u202a",  # left-to-right embedding
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2069",  # pop directional isolate
        "\u2060",  # word joiner
        "\ufeff",  # zero width no-break space
        "\u00ad",  # soft hyphen
        "\U000e0041",  # tag character
    ],
)
def test_invisible_format_characters_rejected(char):
    with pytest.raises(CanonError, match="forbidden character"):
        check_text(f"a{char}b", multiline=True)


@pytest.mark.parametrize("char", ["\u2028", "\u2029"])
def test_line_and_paragraph_separators_rejected(char):
    with pytest.raises(CanonError, match="forbidden character"):
        check_text(f"a{char}b", multiline=True)


@pytest.mark.parametrize(
    "char",
    [
        "\ue000",  # private use
        "\U000f0000",  # supplementary private use
        "\u0378",  # unassigned in Unicode 15.0
        "\uffff",  # noncharacter
        "\ud800",  # lone surrogate
    ],
)
def test_private_use_unassigned_and_surrogates_rejected(char):
    with pytest.raises(CanonError):
        check_text(f"a{char}b")


def test_surrounding_whitespace_is_significant():
    assert check_text(" a ") == " a "
    assert canonical_json("a") != canonical_json("a ")
    assert canonical_json("a") != canonical_json(" a")


@pytest.mark.parametrize("value", [None, 1, b"text", ["a"], _StrSubclass("a")])
def test_non_string_text_rejected(value):
    with pytest.raises(CanonError):
        check_text(value)


# --- Action hash -------------------------------------------------------------

REFUND_ARGS = {"amount": "100.00", "currency": "EUR"}
REFUND_PREIMAGE = (
    b'{"args":{"amount":"100.00","currency":"EUR"},'
    b'"canon_version":1,"resource_id":"acct_1","tool":"issue_refund"}'
)


def test_action_hash_golden_vector():
    expected = "sha256:77ecbf1c5826d274f4b80a2a1be7a80b031f11cb1af8ebe7912732d3c808fa38"
    assert "sha256:" + hashlib.sha256(REFUND_PREIMAGE).hexdigest() == expected
    assert action_hash("issue_refund", "acct_1", REFUND_ARGS) == expected


def test_action_hash_golden_vector_without_resource():
    assert action_hash("list_documents", None, {}) == (
        "sha256:03049cdb868e99dde483ea8832e3388e6e91a2d517584dbc9762c422716bf806"
    )


def test_action_hash_format():
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", action_hash("read_document", "doc_1", {}))


def test_action_hash_independent_of_argument_order():
    reordered = {"currency": "EUR", "amount": "100.00"}
    assert action_hash("issue_refund", "acct_1", reordered) == action_hash(
        "issue_refund", "acct_1", REFUND_ARGS
    )


@pytest.mark.parametrize(
    ("tool", "resource_id", "args"),
    [
        ("get_balance", "acct_1", REFUND_ARGS),
        ("issue_refund", "acct_2", REFUND_ARGS),
        ("issue_refund", "acct_10", REFUND_ARGS),
        ("issue_refund", None, REFUND_ARGS),
        ("issue_refund", "acct_1", {"amount": "100.01", "currency": "EUR"}),
        ("issue_refund", "acct_1", {"amount": "1000.00", "currency": "EUR"}),
        ("issue_refund", "acct_1", {"amount": "100.00", "currency": "USD"}),
        ("issue_refund", "acct_1", {"amount": "100.00"}),
        ("issue_refund", "acct_1", {**REFUND_ARGS, "extra": ""}),
    ],
)
def test_action_hash_changes_with_any_component(tool, resource_id, args):
    reference = action_hash("issue_refund", "acct_1", REFUND_ARGS)
    assert action_hash(tool, resource_id, args) != reference


def test_action_hash_is_byte_exact_on_free_text():
    def email(body):
        return action_hash("send_email", None, {"to": "contact_1", "subject": "s", "body": body})

    assert email("hello") != email("hello ")
    assert email("hello") != email("Hello")
    assert email("a\nb") != email("a b")


def test_action_hash_does_not_confuse_field_boundaries():
    first = action_hash("send_email", None, {"to": "contact_1", "subject": "ab", "body": "c"})
    second = action_hash("send_email", None, {"to": "contact_1", "subject": "a", "body": "bc"})
    assert first != second


def test_canon_version_is_part_of_the_preimage(monkeypatch):
    before = action_hash("issue_refund", "acct_1", REFUND_ARGS)
    monkeypatch.setattr(canon, "CANON_VERSION", 2)
    assert action_hash("issue_refund", "acct_1", REFUND_ARGS) != before


def test_action_hash_rejects_non_canonical_values():
    with pytest.raises(CanonError):
        action_hash("issue_refund", "acct_1", {"amount": 100.0, "currency": "EUR"})
