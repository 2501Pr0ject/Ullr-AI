"""Approver command line: generate a key, list pending requests, sign a decision.

    python -m ullr_ai.approver.cli keygen --out approver.key
    python -m ullr_ai.approver.cli pending --gateway URL --token-file FILE
    python -m ullr_ai.approver.cli decide ACTION_ID approve|reject \\
        --gateway URL --token-file FILE --key approver.key --approver-id human_1

``decide`` shows the request, recomputes the action hash from what it displays,
and asks for confirmation before signing.
"""

import argparse
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ullr_ai.approver import keys
from ullr_ai.gateway import signing
from ullr_ai.gateway.canon import CanonError, action_hash


class ApproverError(Exception):
    """The request cannot be shown or signed safely."""


def fetch_pending(http: httpx.Client, token: str) -> list[dict[str, Any]]:
    response = http.get("/v1/approvals", headers={"Authorization": f"Bearer {token}"})
    if response.status_code != 200:
        raise ApproverError(f"the Gateway refused the listing (HTTP {response.status_code})")
    return response.json()["pending"]


def render(view: dict[str, Any]) -> str:
    """Text shown to the approver before signing."""
    request = view["request"]
    provenance = view["provenance"]
    lines = [
        f"Action        {request['action_id']}",
        f"Tool          {request['tool']} (tier {view['tier']})",
        f"Resource      {request['resource_id']} (version {request['resource_version']})",
        "Arguments",
    ]
    for name, value in sorted(view["args"].items()):
        lines.append(f"  {name}: {value!r}")
    lines += [
        f"Agent         {request['agent_id']} in session {request['session_id']}",
        f"Expires at    {request['expires_at']}",
        "",
    ]
    if provenance["tainted"]:
        sources = ", ".join(provenance["external_sources"])
        lines.append("PROVENANCE    TAINTED: this session has read external content")
        lines.append(f"              external sources observed by the Gateway: {sources}")
    else:
        lines.append("PROVENANCE    clean: no external content observed in this session")
    lines += [
        "",
        "Reason stated by the agent (UNVERIFIED, may be written by an attacker):",
        f"  {view['agent_reason_unverified']!r}",
    ]
    return "\n".join(lines)


def build_decision(
    view: dict[str, Any],
    decision: str,
    approver_id: str,
    private_key: Ed25519PrivateKey,
    now: datetime,
    *,
    expires_in: float | None = None,
) -> dict[str, Any]:
    """Build and sign the decision for one displayed request.

    Refuses to sign if the displayed tool, resource and arguments do not hash
    to the action hash that would be signed. ``expires_in`` shortens the
    validity of the decision; it can never extend the request's own expiry.
    """
    request = dict(view["request"])
    if expires_in is not None:
        sooner = (now + timedelta(seconds=expires_in)).strftime(signing.TIMESTAMP_FORMAT)
        request["expires_at"] = min(sooner, request["expires_at"])
    try:
        displayed = action_hash(request["tool"], request["resource_id"], view["args"])
    except CanonError:
        raise ApproverError("the displayed action cannot be hashed") from None
    if displayed != request["action_hash"]:
        raise ApproverError("the displayed action does not match the action hash to sign")
    try:
        payload = signing.parse_payload(
            {
                **request,
                "decision": decision,
                "approver_id": approver_id,
                "issued_at": now.strftime(signing.TIMESTAMP_FORMAT),
            }
        )
    except signing.SigningError:
        raise ApproverError("the request cannot be turned into a valid decision") from None
    return {"payload": payload.model_dump(), "signature": signing.sign(private_key, payload)}


def decide(
    http: httpx.Client,
    token: str,
    action_id: str,
    decision: str,
    approver_id: str,
    private_key: Ed25519PrivateKey,
    *,
    confirm: Callable[[str], bool],
    now: datetime | None = None,
    expires_in: float | None = None,
) -> str:
    """Show one pending request, ask for confirmation, sign and submit. Returns the new status."""
    matches = [v for v in fetch_pending(http, token) if v["request"]["action_id"] == action_id]
    if len(matches) != 1:
        raise ApproverError("no pending request with this action id")
    view = matches[0]
    body = build_decision(
        view,
        decision,
        approver_id,
        private_key,
        now or datetime.now(UTC),
        expires_in=expires_in,
    )
    if not confirm(render(view)):
        raise ApproverError("not confirmed: nothing was signed or sent")
    response = http.post(f"/v1/approvals/{action_id}/decision", json=body)
    if response.status_code != 200:
        raise ApproverError(f"the Gateway refused the decision (HTTP {response.status_code})")
    return response.json()["status"]


def _ask(text: str) -> bool:
    print(text)
    return input("\nSign this decision? [y/N] ").strip().lower() == "y"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ullr-approver")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create an approver key pair")
    keygen.add_argument("--out", required=True, help="file to write the private key to")

    for name in ("pending", "decide"):
        sub = commands.add_parser(name)
        sub.add_argument("--gateway", required=True, help="base URL of the approver API")
        sub.add_argument("--token-file", required=True, help="approver-channel token file")
        if name == "decide":
            sub.add_argument("action_id")
            sub.add_argument("decision", choices=["approve", "reject"])
            sub.add_argument("--key", required=True, help="approver private key file")
            sub.add_argument("--approver-id", required=True)
            sub.add_argument("--yes", action="store_true", help="sign without asking")
            sub.add_argument(
                "--expires-in", type=float, help="shorten the decision's validity (seconds)"
            )

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            print(keys.generate(args.out))
            return 0
        token = Path(args.token_file).read_text(encoding="ascii").strip()
        with httpx.Client(base_url=args.gateway, timeout=10) as http:
            if args.command == "pending":
                for view in fetch_pending(http, token):
                    print(render(view))
                    print("-" * 72)
                return 0
            status = decide(
                http,
                token,
                args.action_id,
                {"approve": "APPROVE", "reject": "REJECT"}[args.decision],
                args.approver_id,
                keys.load(args.key),
                confirm=(lambda text: print(text) or True) if args.yes else _ask,
                expires_in=args.expires_in,
            )
            print(f"\n{args.action_id}: {status}")
            return 0
    except (ApproverError, OSError, httpx.HTTPError, signing.SigningError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
