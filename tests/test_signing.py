"""Signed decisions: domain separation, strict payload, key handling (T6)."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ullr_ai.gateway import signing
from ullr_ai.gateway.canon import canonical_json
from ullr_ai.gateway.signing import DecisionPayload, SigningError

PAYLOAD = {
    "decision": "APPROVE",
    "action_id": "act_" + "1" * 32,
    "agent_id": "agent_1",
    "session_id": "sess_" + "2" * 32,
    "tool": "delete_document",
    "resource_id": "doc_142",
    "resource_version": 12,
    "action_hash": "sha256:" + "a" * 64,
    "policy_hash": "sha256:" + "b" * 64,
    "canon_version": 1,
    "provenance_version": 4,
    "approver_id": "human_1",
    "nonce": "c" * 32,
    "issued_at": "2026-11-11T10:00:00.000000Z",
    "expires_at": "2026-11-11T10:05:00.000000Z",
}

ALTERED = {
    "decision": "REJECT",
    "action_id": "act_" + "9" * 32,
    "agent_id": "agent_2",
    "session_id": "sess_" + "9" * 32,
    "tool": "update_document",
    "resource_id": "doc_143",
    "resource_version": 13,
    "action_hash": "sha256:" + "9" * 64,
    "policy_hash": "sha256:" + "9" * 64,
    "canon_version": 2,
    "provenance_version": 5,
    "approver_id": "human_2",
    "nonce": "9" * 32,
    "issued_at": "2026-11-11T10:00:01.000000Z",
    "expires_at": "2026-11-11T10:06:00.000000Z",
}


@pytest.fixture(scope="module")
def keys():
    private, public = signing.generate_keypair()
    return signing.load_private_key(private), public


def payload(**overrides):
    return signing.parse_payload({**PAYLOAD, **overrides})


def test_payload_has_exactly_the_fifteen_specified_fields():
    assert set(DecisionPayload.model_fields) == set(PAYLOAD)
    assert len(PAYLOAD) == 15
    assert set(ALTERED) == set(PAYLOAD)


def test_signature_round_trip(keys):
    private, public = keys
    signature = signing.sign(private, payload())
    assert signing.verify(public, payload(), signature)


def test_signed_bytes_are_the_domain_prefix_then_canonical_json():
    expected = b"AGENT-GATEWAY/APPROVAL-DECISION/v1\x00" + canonical_json(PAYLOAD)
    assert signing.signing_input(payload()) == expected
    assert signing.DOMAIN.endswith(b"\x00")


@pytest.mark.parametrize("field", sorted(PAYLOAD))
def test_altering_any_single_field_invalidates_the_signature(keys, field):
    private, public = keys
    signature = signing.sign(private, payload())
    assert not signing.verify(public, payload(**{field: ALTERED[field]}), signature)


def test_null_resource_is_distinct_from_any_resource(keys):
    private, public = keys
    signature = signing.sign(private, payload(resource_id=None, resource_version=0))
    assert signing.verify(public, payload(resource_id=None, resource_version=0), signature)
    assert not signing.verify(public, payload(resource_version=0), signature)


@pytest.mark.parametrize(
    "prefix",
    [
        b"",
        b"AGENT-GATEWAY/APPROVAL-DECISION/v1",  # no separator
        b"AGENT-GATEWAY/APPROVAL-DECISION/v2\x00",
        b"AGENT-GATEWAY/OTHER-CONTEXT/v1\x00",
        b"agent-gateway/approval-decision/v1\x00",
    ],
)
def test_signature_made_in_another_domain_is_rejected(keys, prefix):
    private, public = keys
    foreign = private.sign(prefix + canonical_json(PAYLOAD))
    assert not signing.verify(public, payload(), base64.b64encode(foreign).decode())


def test_signature_from_another_key_is_rejected(keys):
    _, public = keys
    other = Ed25519PrivateKey.generate()
    assert not signing.verify(public, payload(), signing.sign(other, payload()))


@pytest.mark.parametrize(
    "signature",
    [
        None,
        "",
        "not base64!",
        base64.b64encode(b"\x00" * 64).decode(),
        base64.b64encode(b"\x00" * 63).decode(),
        base64.b64encode(b"\x00" * 65).decode(),
        b"bytes",
        123,
        ["sig"],
    ],
)
def test_malformed_signature_is_rejected(keys, signature):
    _, public = keys
    assert not signing.verify(public, payload(), signature)


def test_non_canonical_base64_of_a_valid_signature_is_rejected(keys):
    private, public = keys
    signature = signing.sign(private, payload())
    assert signing.verify(public, payload(), signature)
    assert not signing.verify(public, payload(), signature + "\n")
    assert not signing.verify(public, payload(), " " + signature)
    assert not signing.verify(public, payload(), signature.rstrip("="))


@pytest.mark.parametrize("public", ["", "abc", base64.b64encode(b"\x01" * 31).decode(), None])
def test_malformed_public_key_never_verifies(keys, public):
    private, _ = keys
    assert not signing.verify(public, payload(), signing.sign(private, payload()))


@pytest.mark.parametrize(
    "overrides",
    [
        {"decision": "approve"},
        {"decision": "ALLOW"},
        {"decision": True},
        {"action_id": "act_1"},
        {"agent_id": "human_1"},
        {"session_id": "sess_1"},
        {"tool": "Delete_Document"},
        {"resource_id": "./doc_1"},
        {"resource_version": "12"},
        {"resource_version": 12.0},
        {"resource_version": -1},
        {"resource_version": True},
        {"action_hash": "a" * 64},
        {"policy_hash": "sha256:" + "A" * 64},
        {"canon_version": "1"},
        {"provenance_version": None},
        {"approver_id": "Human_1"},
        {"approver_id": ""},
        {"nonce": "c" * 31},
        {"issued_at": "2026-11-11T10:00:00Z"},
        {"expires_at": "2026-11-11 10:05:00.000000Z"},
        {"expires_at": 1794000000},
        {"extra": "x"},
        {"public_key": "attacker-key"},
    ],
)
def test_malformed_payload_is_rejected(overrides):
    with pytest.raises(SigningError):
        signing.parse_payload({**PAYLOAD, **overrides})


@pytest.mark.parametrize("field", sorted(PAYLOAD))
def test_every_payload_field_is_required(field):
    incomplete = {key: value for key, value in PAYLOAD.items() if key != field}
    with pytest.raises(SigningError):
        signing.parse_payload(incomplete)


@pytest.mark.parametrize("raw", [None, [], "payload", 1])
def test_payload_must_be_an_object(raw):
    with pytest.raises(SigningError):
        signing.parse_payload(raw)


def test_generated_keys_are_distinct_and_load(keys):
    private_a, public_a = signing.generate_keypair()
    private_b, public_b = signing.generate_keypair()
    assert private_a != private_b
    assert public_a != public_b
    assert signing.public_key_of(signing.load_private_key(private_a)) == public_a
    assert len(base64.b64decode(public_a)) == 32


@pytest.mark.parametrize("encoded", ["", "abc", base64.b64encode(b"\x01" * 31).decode(), None, 5])
def test_malformed_private_key_is_rejected(encoded):
    with pytest.raises(SigningError):
        signing.load_private_key(encoded)
