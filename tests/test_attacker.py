"""The attacker's own detectors: a broken detector would report a false 'absent'."""

import asyncio
import errno
import hashlib
import json
import socket

import httpx
import pytest
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


# --- Scanner: every successful connection is classified from its endpoints ---


def listening_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    return server, server.getsockname()[1]


def closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_genuine_listener_is_an_open_port_with_distinct_endpoints():
    server, port = listening_port()
    try:
        result = asyncio.run(run._scan("127.0.0.1", range(port, port + 1), 2.0, 4))
        single = run.tcp_connect("127.0.0.1", port)
    finally:
        server.close()
    assert result["open"] == [port]
    assert result["self_connect"] == []
    connection = result["connections"][0]
    assert connection["classification"] == "open"
    assert connection["peer"] == ["127.0.0.1", port]
    assert connection["local"] != connection["peer"]
    assert single["result"] == "open"
    assert single["peer"] == ["127.0.0.1", port]

    # Not on the allow-list: an unexplained open port fails the record.
    assert run.scan_outcome("127.0.0.1", result, [])["outcome"] == "allowed"
    assert run.scan_outcome("127.0.0.1", result, [])["unexpected"] == [port]
    # On the allow-list: expected.
    assert run.scan_outcome("127.0.0.1", result, [f"127.0.0.1:{port}"])["outcome"] == "blocked"


def test_refused_connection():
    port = closed_port()
    result = asyncio.run(run._scan("127.0.0.1", range(port, port + 1), 2.0, 4))
    assert result["counts"] == {"tcp_refused": 1}
    assert result["connections"] == []
    verdict = run.scan_outcome("127.0.0.1", result, [])
    assert (verdict["outcome"], verdict["cause"]) == ("blocked", "tcp_refused")
    assert run.tcp_connect("127.0.0.1", port) == {
        "result": "tcp_refused",
        "local": None,
        "peer": None,
    }


def test_timeout_is_its_own_cause(monkeypatch):
    async def never_answers(address, port):
        await asyncio.sleep(5)

    monkeypatch.setattr(run.asyncio, "open_connection", never_answers)
    result = asyncio.run(run._scan("192.0.2.1", range(1, 4), 0.05, 4))
    assert result["counts"] == {"timeout": 3}
    assert result["connections"] == []
    verdict = run.scan_outcome("192.0.2.1", result, [])
    assert (verdict["outcome"], verdict["cause"]) == ("blocked", "timeout")


class FakeWriter:
    def __init__(self, local, peer):
        self.endpoints = {"sockname": local, "peername": peer}

    def get_extra_info(self, name):
        return self.endpoints[name]

    def close(self):
        pass


def test_self_connection_is_reported_as_its_own_outcome(monkeypatch):
    """Local endpoint == peer endpoint: classified from the socket, kept raw, not hidden."""

    async def connects_to_itself(address, port):
        if port == 40001:
            return None, FakeWriter((address, port), (address, port))
        raise ConnectionRefusedError

    monkeypatch.setattr(run.asyncio, "open_connection", connects_to_itself)
    result = asyncio.run(run._scan("172.30.0.10", range(40000, 40003), 1.0, 4))
    assert result["self_connect"] == [40001]
    assert result["open"] == []
    assert result["counts"] == {"tcp_refused": 2, "self_connect": 1}
    assert result["connections"] == [
        {
            "port": 40001,
            "classification": "self_connect",
            "local": ["172.30.0.10", 40001],
            "peer": ["172.30.0.10", 40001],
        }
    ]
    verdict = run.scan_outcome("172.30.0.10", result, [])
    assert verdict["outcome"] == "self_connect"
    assert verdict["unexpected"] == []


def test_real_self_connection_has_identical_endpoints():
    """A socket bound to a port and connected to that same port, where the OS allows it."""
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        try:
            probe.connect(("127.0.0.1", port))
        except OSError:
            pytest.skip("this operating system does not allow a TCP self-connection")
        local, peer = probe.getsockname(), probe.getpeername()
    finally:
        probe.close()
    assert local == peer
    assert run.classify_connection(local, peer) == "self_connect"


def test_only_identical_endpoints_count_as_self_connection():
    assert run.classify_connection(("10.0.0.1", 5000), ("10.0.0.1", 5000)) == "self_connect"
    assert run.classify_connection(("10.0.0.1", 5000), ("10.0.0.1", 5001)) == "open"
    assert run.classify_connection(("10.0.0.1", 5000), ("10.0.0.2", 5000)) == "open"
    assert run.classify_connection(("127.0.0.1", 5000), ("10.0.0.1", 5000)) == "open"
    assert run.classify_connection(None, ("10.0.0.1", 5000)) == "open"
    assert run.classify_connection(("10.0.0.1", 5000), None) == "open"


def test_self_connection_never_hides_an_unexplained_open_port():
    result = {
        "open": [8080],
        "self_connect": [40001],
        "connections": [],
        "counts": {"open": 1, "self_connect": 1, "tcp_refused": 10},
    }
    verdict = run.scan_outcome("172.30.0.10", result, [])
    assert verdict["outcome"] == "allowed"
    assert verdict["unexpected"] == [8080]


def test_scan_record_keeps_the_outcome_name_and_the_raw_connections(capsys):
    connection = {
        "port": 40001,
        "classification": "self_connect",
        "local": ["172.30.0.10", 40001],
        "peer": ["172.30.0.10", 40001],
    }
    run.emit(
        "N3-scan-x",
        "network",
        "t",
        "a",
        "self_connect",
        accepted=("self_connect",),
        successful_connections=[connection],
    )
    run.emit("N3-scan-y", "network", "t", "a", "allowed", accepted=("self_connect",))
    first, second = (json.loads(line) for line in capsys.readouterr().out.splitlines())
    assert (first["outcome"], first["expected"], first["passed"]) == (
        "self_connect",
        "blocked",
        True,
    )
    assert first["details"]["successful_connections"] == [connection]
    assert (second["outcome"], second["passed"]) == ("allowed", False)


def test_single_attempt_outcome_names():
    assert run.single_outcome("open") == "allowed"
    assert run.single_outcome("self_connect") == "self_connect"
    assert run.single_outcome("tcp_refused") == "blocked"
