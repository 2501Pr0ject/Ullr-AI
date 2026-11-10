"""Controller commands: the trusted party that prepares and observes an episode.

Runs in the controller container, which is on the admin and control networks
only and never on a network shared with the agent. It hands the episode token
to the agent through a volume the agent mounts read-only.

    python -m ullr_ai.bench.controller <command> [args]

Every command prints one JSON document on stdout. The agent token is never printed.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from ullr_ai.serve import read_secret

TOKEN_FILE = "agent_token"  # noqa: S105 (a file name)


class Controller:
    def __init__(
        self,
        tools_admin: httpx.Client,
        tools_admin_token: str,
        gateway_admin: httpx.Client | None,
        gateway_admin_token: str | None,
        episodes_dir: Path,
    ) -> None:
        self._tools = tools_admin
        self._tools_auth = {"Authorization": f"Bearer {tools_admin_token}"}
        self._gateway = gateway_admin
        self._gateway_auth = {"Authorization": f"Bearer {gateway_admin_token}"}
        self._episodes_dir = episodes_dir

    def _gateway_client(self) -> httpx.Client:
        if self._gateway is None:
            raise RuntimeError("this controller has no Gateway (baseline project)")
        return self._gateway

    @staticmethod
    def _checked(response: httpx.Response, *expected: int) -> Any:
        if response.status_code not in (expected or (200,)):
            raise RuntimeError(f"unexpected HTTP {response.status_code} from {response.url.path}")
        return response.json()

    # --- Tools service -------------------------------------------------------

    def seed(self, seed: dict[str, Any]) -> dict[str, Any]:
        return self._checked(
            self._tools.post("/admin/reset", json={"seed": seed}, headers=self._tools_auth)
        )

    def snapshot(self) -> dict[str, Any]:
        state = self._checked(self._tools.get("/admin/snapshot", headers=self._tools_auth))
        log = self._checked(self._tools.get("/admin/executions", headers=self._tools_auth))
        return {"state": state, "executions": log["executions"]}

    def fault_add(self, tool: str, resource_id: str | None, on_call: int, hold: str) -> Any:
        body = {"tool": tool, "resource_id": resource_id, "on_call": on_call, "hold": hold}
        return self._checked(
            self._tools.post("/admin/faults", json=body, headers=self._tools_auth), 201
        )

    def fault_list(self) -> Any:
        return self._checked(self._tools.get("/admin/faults", headers=self._tools_auth))

    def fault_release(self, fault_id: int, action: str) -> Any:
        return self._checked(
            self._tools.post(
                f"/admin/faults/{fault_id}/release",
                json={"action": action},
                headers=self._tools_auth,
            )
        )

    # --- Gateway -------------------------------------------------------------

    def session(self, agent_id: str, slot: str) -> dict[str, Any]:
        """Create a session and hand its token over through the agent's volume.

        The file is replaced atomically, so the volume holds one token: the current one.
        """
        created = self._checked(
            self._gateway_client().post(
                "/admin/sessions", json={"agent_id": agent_id}, headers=self._gateway_auth
            ),
            201,
        )
        directory = self._episodes_dir / slot
        temporary = directory / (TOKEN_FILE + ".new")
        temporary.write_text(created["agent_token"] + "\n", encoding="ascii")
        os.replace(temporary, directory / TOKEN_FILE)
        return {"session_id": created["session_id"], "agent_id": created["agent_id"]}

    def revoke(self, session_id: str) -> Any:
        return self._checked(
            self._gateway_client().post(
                f"/admin/sessions/{session_id}/revoke", headers=self._gateway_auth
            )
        )

    def state(self) -> Any:
        return self._checked(self._gateway_client().get("/admin/state", headers=self._gateway_auth))

    def wait(self, timeout: float = 90.0) -> dict[str, Any]:
        """Wait until the admin APIs answer."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.fault_list()
                if self._gateway is not None:
                    self.state()
                return {"ready": True}
            except (httpx.HTTPError, RuntimeError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)


def from_environment() -> Controller:
    env = os.environ
    gateway_url = env.get("ULLR_GATEWAY_ADMIN_URL")
    return Controller(
        httpx.Client(base_url=env["ULLR_TOOLS_ADMIN_URL"], timeout=15.0),
        read_secret(env, "tools_admin_token"),
        httpx.Client(base_url=gateway_url, timeout=15.0) if gateway_url else None,
        read_secret(env, "gateway_admin_token") if gateway_url else None,
        Path(env.get("ULLR_EPISODES_DIR", "/episodes")),
    )


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m ullr_ai.bench.controller <command> [args]", file=sys.stderr)
        return 2
    command, args = argv[0], argv[1:]
    controller = from_environment()
    if command == "wait":
        result = controller.wait()
    elif command == "seed":
        result = controller.seed(json.loads(sys.stdin.read()))
    elif command == "snapshot":
        result = controller.snapshot()
    elif command == "session":
        result = controller.session(args[0], args[1])
    elif command == "revoke":
        result = controller.revoke(args[0])
    elif command == "state":
        result = controller.state()
    elif command == "fault-add":
        resource_id = None if args[1] == "-" else args[1]
        result = controller.fault_add(args[0], resource_id, int(args[2]), args[3])
    elif command == "fault-list":
        result = controller.fault_list()
    elif command == "fault-release":
        result = controller.fault_release(int(args[0]), args[1])
    else:
        print(f"unknown command: {command}", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
