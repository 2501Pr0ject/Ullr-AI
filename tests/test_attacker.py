"""The attacker's own detectors: a broken detector would report a false 'absent'."""

import errno
import hashlib

import httpx
from attacks import driver, run
from scripts import gen_secrets

SECRET = b"s3cr3t-" + b"Ab9_" * 14 + b"xyz"  # 64 characters, token-like
KEY = b"q83vEjRWeJAbzN7x5nR0mQ1T0a2b3c4d5e6f7g8h9i0="  # base64 with padding
HASHES = {
    "executor_token": hashlib.sha256(SECRET).hexdigest(),
    "approver_private_key": hashlib.sha256(KEY).hexdigest(),
}


def test_secret_is_found_in_the_forms_it_would_leak_in():
    for data in (
        SECRET,
        SECRET + b"\n",
        b"EXECUTOR_TOKEN=" + SECRET,
        b'{"token": "' + SECRET + b'"}',
        b"Authorization: Bearer " + SECRET + b"\r\n",
        b"export ULLR_EXECUTOR_TOKEN='" + SECRET + b"'\n",
        b"\x00".join([b"PATH=/usr/bin", b"T=" + SECRET]),
        b"line one\n" + SECRET + b"\nline three\n",
    ):
        assert run.matches(data, HASHES) == {"executor_token"}


def test_base64_key_with_padding_is_found():
    for data in (KEY, KEY + b"\n", b'key: "' + KEY + b'"', b"KEY=" + KEY):
        assert run.matches(data, HASHES) == {"approver_private_key"}


def test_both_secrets_in_one_file():
    assert run.matches(b"a=" + SECRET + b"\nb=" + KEY + b"\n", HASHES) == set(HASHES)


def test_other_tokens_do_not_match():
    for data in (b"", b"hello", SECRET[:-1], SECRET + b"x", SECRET.lower(), b"A" * 64):
        assert run.matches(data, HASHES) == set()


def test_detector_only_needs_hashes():
    assert SECRET.decode() not in str(HASHES)


def test_connection_failures_are_classified_by_cause():
    assert run.connect_cause(ConnectionRefusedError()) == "tcp_refused"
    assert run.connect_cause(TimeoutError()) == "timeout"
    assert run.connect_cause(OSError(errno.ENETUNREACH, "unreachable")) == "no_route"
    assert run.connect_cause(OSError(errno.EHOSTUNREACH, "no route")) == "no_route"
    assert run.connect_cause(run.socket.gaierror(-2, "unknown")) == "dns"
    assert run.connect_cause(OSError(errno.EACCES, "denied")) == "other:EACCES"


def test_http_refusals_are_classified_by_cause():
    def reply(status, body):
        return httpx.Response(status, json=body)

    assert run.http_cause(reply(401, {"error": "unauthorized"})) == "auth_refused"
    assert run.http_cause(reply(403, {"error": "route_forbidden"})) == "auth_refused"
    assert run.http_cause(reply(404, {"error": "not_found"})) == "route_absent"
    assert run.http_cause(reply(403, {"error": "approval_required"})) == (
        "policy_refused:approval_required"
    )
    assert run.http_cause(reply(403, {"reason": "amount_over_limit"})) == (
        "policy_refused:amount_over_limit"
    )
    assert run.http_cause(reply(409, {"error": "action_mismatch"})) == (
        "policy_refused:action_mismatch"
    )


def test_tools_side_counts_come_from_the_tools_state():
    snapshot = {
        "state": {
            "refunds": [
                {"account_id": "acct_1"},
                {"account_id": "acct_1"},
                {"account_id": "acct_3"},
            ],
            "documents": [
                {"id": "doc_1", "deleted": 1, "version": 2},
                {"id": "doc_2", "deleted": 0, "version": 3},
                {"id": "doc_3", "deleted": 0, "version": 1},
            ],
            "outbound_mail": [{}],
            "config": [{"id": "cfg_1", "version": 1}],
        },
        "executions": [{"status": "EXECUTED"}, {"status": "FAILED"}],
    }
    counts = driver.tools_counts(snapshot)
    assert counts["refunds"] == {"acct_1": 2, "acct_3": 1}
    assert counts["deleted"] == ["doc_1"]
    assert counts["modified"] == ["doc_1", "doc_2"]
    assert counts["mail"] == 1
    assert len(counts["executed"]) == 1


def test_a_record_fails_when_the_tools_side_count_differs():
    counts = {
        "refunds": {"acct_1": 2},  # the approval was executed twice
        "deleted": [],
        "modified": [],
        "mail": 1,
        "executed": [{}] * 8,
        "log": [],
    }
    records = [
        driver.record("A3-reuse-1", "api", "t", "a", "blocked", expected_executions=1),
        driver.record(
            "F1-approved-action",
            "api",
            "t",
            "a",
            "allowed",
            expected="allowed",
            expected_executions=1,
        ),
        driver.record("N2-name-tools-admin", "network", "t", "a", "blocked"),
    ]
    driver.fill_tools_counts(records, counts)
    assert [r["tools_executions"] for r in records] == [2, 1, 1]
    assert [r["passed"] for r in records] == [False, True, False]


def test_privileged_secret_list_covers_every_generated_secret():
    assert set(driver.PRIVILEGED_SECRETS) == {*gen_secrets.TOKENS, "approver_private_key"}
