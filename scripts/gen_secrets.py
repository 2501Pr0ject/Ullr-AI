"""Generate the secrets of the local stack into ``secrets/`` (git-ignored).

    uv run python scripts/gen_secrets.py [--force]

Each file is delivered to exactly the containers listed in docker/compose.yaml.
The approver private key goes to the approver container only; the Gateway
gets the public registry.
"""

import secrets
import sys
from pathlib import Path

from ullr_ai.gateway import signing

ROOT = Path(__file__).resolve().parents[1]
TOKENS = (
    "executor_token",
    "tools_admin_token",
    "gateway_admin_token",
    "approver_channel_token",
    "baseline_executor_token",
    "baseline_tools_admin_token",
)


def main(argv: list[str]) -> int:
    target = ROOT / "secrets"
    if target.exists() and any(target.iterdir()) and "--force" not in argv:
        print("secrets/ already exists; use --force to replace it", file=sys.stderr)
        return 1
    target.mkdir(mode=0o700, exist_ok=True)
    target.chmod(0o700)
    for name in TOKENS:
        (target / name).write_text(secrets.token_urlsafe(48) + "\n", encoding="ascii")
    private, public = signing.generate_keypair()
    (target / "approver_private_key").write_text(private + "\n", encoding="ascii")
    (target / "approvers.yaml").write_text(f'approvers:\n  human_1: "{public}"\n', encoding="ascii")
    print(f"wrote {len(TOKENS) + 2} files to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
