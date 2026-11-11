"""L3 runner: the same agent on every task, with and without the Gateway.

    uv run python -m ullr_ai.bench.runner --tasks tasks --out results/l3/NAME \\
        [--only A03,A09,B01] [--conditions baseline,AP-rubber,...] [--seed N]

Runs on the host and drives the two Compose projects, as the L2 driver does.
Every episode starts from a stack created for it and removed after it, in both
routings: no database, volume, session or log survives from one episode or
condition to the next. Outcomes are read from the Tools service only.

Written to the output directory, which must not exist yet:
- ``episodes.jsonl``: one row per episode, skipped and failed ones included;
- ``transcripts.jsonl``: the agent's transcript and the approver's log;
- ``summary.json``: the metrics of EVALUATION_PLAN.md section 7;
- ``manifest.json``: what is needed to tell which run this was.
"""

import argparse
import hashlib
import json
import random
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from ullr_ai.agent import prompt, tools
from ullr_ai.bench import metrics
from ullr_ai.bench.evaluate import evaluate
from ullr_ai.bench.tasks import Task, UnsupportedFault, fault_rules, load_tasks, seed_of
from ullr_ai.gateway import approvals
from ullr_ai.gateway.canon import CANON_VERSION
from ullr_ai.gateway.policy import load_policy

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = {
    "gateway": ["docker", "compose", "-f", str(ROOT / "docker" / "compose.yaml")],
    "direct": ["docker", "compose", "-f", str(ROOT / "docker" / "baseline" / "compose.yaml")],
}
AGENT_ENV = {
    "gateway": {
        "ULLR_GATEWAY_URL": "http://gateway-api:8000",
        "ULLR_RELAY_URL": "http://llm-relay:8000",
    },
    "direct": {
        "ULLR_TOOLS_URL": "http://tools-executor:8000",
        "ULLR_RELAY_URL": "http://llm-relay:8000",
    },
}
MODEL = "qwen3:8b"
OLLAMA = "http://127.0.0.1:11434"  # host loopback; only read for the manifest
CONDITIONS = (metrics.BASELINE, *metrics.PROTECTED)
AGENT_ID = "agent_1"
EPISODE_TIME_LIMIT = 900.0
SETTLE_TIMEOUT = 60.0


def sh(command: list[str], *, stdin: str | None = None, timeout: float = 1800) -> str:
    done = subprocess.run(  # noqa: S603 (fixed commands, no shell)
        command, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
    )
    if done.returncode != 0:
        raise RuntimeError(f"{' '.join(command[:6])} failed: {done.stderr.strip()[-400:]}")
    return done.stdout


class Stack:
    """One Compose project, created for one episode."""

    def __init__(self, routing: str) -> None:
        self.routing = routing
        self._compose = COMPOSE[routing]

    def up(self) -> None:
        self.down()
        sh([*self._compose, "up", "-d", "--wait"])
        self.controller("wait")

    def down(self) -> None:
        sh([*self._compose, "down", "-v", "--remove-orphans"])

    def exec(self, service: str, *command: str, stdin: str | None = None, env=None) -> str:
        flags = [flag for name, value in (env or {}).items() for flag in ("-e", f"{name}={value}")]
        return sh([*self._compose, "exec", "-T", *flags, service, *command], stdin=stdin)

    def controller(self, *args: str, stdin: str | None = None) -> Any:
        output = self.exec(
            "controller", "python", "-m", "ullr_ai.bench.controller", *args, stdin=stdin
        )
        return json.loads(output)

    def start_approver(self, profile: str, required_actions: list[dict[str, Any]]):
        process = subprocess.Popen(  # noqa: S603
            [
                *self._compose,
                "exec",
                "-T",
                "approver",
                "python",
                "-m",
                "ullr_ai.bench.approvers",
                "--gateway",
                "http://gateway-approver:8000",
                "--token-file",
                "/run/secrets/approver_channel_token",
                "--key",
                "/run/secrets/approver_private_key",
                "--approver-id",
                "human_1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        config = {"profile": profile, "required_actions": required_actions}
        process.stdin.write(json.dumps(config) + "\n")
        process.stdin.flush()
        return process

    def relay_models(self) -> dict[str, str]:
        """Model digests the relay reported when it started."""
        for line in sh([*self._compose, "logs", "--no-log-prefix", "llm-relay"]).splitlines():
            if '"relay_ready"' in line:
                return json.loads(line)["models"]
        raise RuntimeError("the relay did not report its models")


def feed_statuses(stack: Stack, approver: Any, done: threading.Event) -> None:
    """Pass the Gateway's action statuses to the approver process until the agent is done."""
    while not done.is_set():
        try:
            actions = stack.controller("state")["actions"]
            statuses = {action["action_id"]: action["status"] for action in actions}
            approver.stdin.write(json.dumps({"statuses": statuses}) + "\n")
            approver.stdin.flush()
        except (RuntimeError, subprocess.SubprocessError, OSError, ValueError, KeyError):
            return
        done.wait(0.5)


def condition_order(task_id: str, conditions: list[str], order_seed: int) -> list[str]:
    """Order of the conditions for one task: a fixed function of the seed and the task."""
    shuffled = sorted(conditions)
    random.Random(f"{order_seed}:{task_id}").shuffle(shuffled)  # noqa: S311 (not security)
    return shuffled


def agent_summary(transcript: dict[str, Any]) -> dict[str, Any]:
    """What the agent attempted, from its own transcript. Never used for outcomes."""
    calls = [e for e in transcript["events"] if e["type"] == "tool_call"]
    forwarded = [call for call in calls if call.get("forwarded")]
    return {
        "end_reason": transcript["end_reason"],
        "model_turns": sum(1 for e in transcript["events"] if e["type"] == "model"),
        "tool_calls": len(calls),
        "forwarded_calls": len(forwarded),
        "unknown_tools": [call["name"] for call in calls if not call["known_tool"]],
        "repeated_calls": sum(1 for call in forwarded if call["repeat_of"] is not None),
        "pending_replies": sum(1 for c in forwarded if c["reply"]["status"] == "pending_approval"),
        "rejected_replies": sum(1 for c in forwarded if c["reply"]["status"] == "rejected"),
        "execute_attempts": sum(call.get("execute_attempts", 0) for call in forwarded),
        "latency_ms": [call["latency_ms"] for call in forwarded],
    }


def build_row(
    base: dict[str, Any],
    task: Task,
    seed: dict[str, Any],
    transcript: dict[str, Any],
    snapshot: dict[str, Any],
    gateway_state: dict[str, Any] | None,
    registry: dict[str, str],
) -> dict[str, Any]:
    """Score one finished episode. Pure: everything it needs is passed in."""
    evaluation = evaluate(task.ground_truth, seed, snapshot["state"], snapshot["executions"])
    row = {
        **base,
        "status": "completed",
        "agent": agent_summary(transcript),
        "evaluation": evaluation,
        "gateway": None,
        "bypass": None,
    }
    if gateway_state is not None:
        actions = gateway_state["actions"]
        row["gateway"] = metrics.gateway_summary(actions, task.ground_truth, evaluation)
        row["gateway"]["audit_chain_ok"] = gateway_state["audit"]["ok"]
        row["bypass"] = {
            "check": metrics.BYPASS_CHECK,
            "effective_executions": evaluation["effective_executions"],
            "unbacked": metrics.unbacked_executions(snapshot["executions"], actions, registry),
        }
    return row


def run_episode(
    task: Task, condition: str, base: dict[str, Any], registry: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """One episode. Returns ``(row, transcript record)``."""
    routing = base["routing"]
    try:
        rules = fault_rules(task)
    except UnsupportedFault as exc:
        return {**base, "status": "skipped", "skip_reason": str(exc)}, {}

    seed = seed_of(task)
    stack = Stack(routing)
    timings: dict[str, float] = {}
    started = time.monotonic()
    approver = None
    approver_log: list[dict[str, Any]] = []
    try:
        stack.up()
        timings["stack_up_s"] = round(time.monotonic() - started, 1)
        stack.controller("seed", stdin=json.dumps(seed))
        for rule in rules:
            stack.controller(
                "fault-add",
                rule["tool"],
                rule["resource_id"] or "-",
                str(rule["on_call"]),
                rule["hold"],
                rule["auto_release"],
            )
        session_id = None
        if routing == "gateway":
            session_id = stack.controller("session", AGENT_ID, "1")["session_id"]
            approver = stack.start_approver(condition, task.ground_truth["required_actions"])

        episode = {
            "routing": routing,
            "first_message": prompt.first_message(task.state, task.data["user_prompt"]),
            "max_steps": task.max_steps,
            "model": base["model"],
            "seed": base["seed"],
            "temperature": base["temperature"],
            "time_limit": EPISODE_TIME_LIMIT,
        }
        # The oracle is told what the Gateway recorded about the actions, so that
        # an approval whose action definitively failed gives its slot back.
        agent_done = threading.Event()
        feeder = None
        if condition == "AP-oracle":
            feeder = threading.Thread(
                target=feed_statuses, args=(stack, approver, agent_done), daemon=True
            )
            feeder.start()

        agent_started = time.monotonic()
        transcript = json.loads(
            stack.exec(
                "agent",
                "python",
                "-m",
                "ullr_ai.agent.run",
                stdin=json.dumps(episode),
                env=AGENT_ENV[routing],
            )
        )
        timings["agent_s"] = round(time.monotonic() - agent_started, 1)

        gateway_state = None
        agent_done.set()
        if feeder is not None:
            feeder.join(timeout=30)
        if routing == "gateway":
            # Closing its stdin is what stops the approver loop.
            output, _ = approver.communicate(timeout=30)
            approver_log = [json.loads(line) for line in output.splitlines() if line.strip()]
            approver = None
            # Let in-flight executions settle; what is still open after that is
            # reported as open. The state is read before the session is revoked.
            deadline = time.monotonic() + SETTLE_TIMEOUT
            while True:
                gateway_state = stack.controller("state")
                unsettled = [
                    a for a in gateway_state["actions"] if a["status"] in ("EXECUTING", "UNKNOWN")
                ]
                if not unsettled or time.monotonic() > deadline:
                    break
                time.sleep(1.0)
        snapshot = stack.controller("snapshot")
        if session_id is not None:
            stack.controller("revoke", session_id)

        row = build_row(base, task, seed, transcript, snapshot, gateway_state, registry)
        row["relay_models"] = stack.relay_models()
        row["prompt_hashes_match"] = (
            transcript["system_prompt_hash"] == prompt.system_prompt_hash()
            and transcript["tool_definitions_hash"] == tools.definitions_hash()
        )
        record = {"transcript": transcript, "approver_log": approver_log, "snapshot": snapshot}
    except (RuntimeError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        row = {**base, "status": "error", "error": f"{type(exc).__name__}: {exc}"[:500]}
        record = {"approver_log": approver_log}
    finally:
        if approver is not None:
            approver.kill()
        try:
            stack.down()
        except (RuntimeError, subprocess.SubprocessError):
            print("stack could not be removed", file=sys.stderr)
    timings["total_s"] = round(time.monotonic() - started, 1)
    row["durations"] = timings
    return row, record


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(args: argparse.Namespace, tasks: list[Task], orders: dict[str, list[str]]) -> dict:
    status = sh(["git", "-C", str(ROOT), "status", "--porcelain"])
    try:
        ollama = httpx.get(OLLAMA + "/api/version", timeout=5).json().get("version")
    except (httpx.HTTPError, ValueError):
        ollama = None
    return {
        "code_commit": sh(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(),
        "working_tree_clean": status.strip() == "",
        "image_id": sh(
            ["docker", "image", "inspect", "ullr-ai:local", "--format", "{{.Id}}"]
        ).strip(),
        "relay": "llm-relay service of the image above",
        "ollama_version": ollama,
        "model": MODEL,
        "model_digests": None,  # filled from the relay's own start-up report
        "policy_hash": load_policy(ROOT / "policies" / "default.yaml").policy_hash,
        "canon_version": CANON_VERSION,
        "system_prompt_hash": prompt.system_prompt_hash(),
        "tool_definitions_hash": tools.definitions_hash(),
        "temperature": args.temperature,
        "seed": args.seed,
        "think": False,
        "repetitions": args.repetitions,
        "order_seed": args.order_seed,
        "condition_order": orders,
        "tasks_directory": str(args.tasks),
        "tasks": {
            task.id: {
                "file_hash": _sha256(task.path),
                "max_steps": task.max_steps,
                "faults": task.data.get("faults", []),
            }
            for task in tasks
        },
        # Faults are deterministic rules (nth matching call): they have no seed.
        "fault_seed": None,
        "python": sys.version.split()[0],
        "docker": sh(["docker", "version", "--format", "{{.Server.Version}}"]).strip(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ullr-l3")
    parser.add_argument("--tasks", type=Path, default=ROOT / "tasks")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", default="", help="comma-separated task ids")
    parser.add_argument("--conditions", default=",".join(CONDITIONS))
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--seed", type=int, default=20261115)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--order-seed", type=int, default=1)
    args = parser.parse_args(argv)

    if args.out.exists():
        print(f"{args.out} already exists: refusing to overwrite a run", file=sys.stderr)
        return 1
    conditions = args.conditions.split(",")
    if not set(conditions) <= set(CONDITIONS):
        print("unknown condition", file=sys.stderr)
        return 2
    tasks = load_tasks(args.tasks)
    if args.only:
        wanted = args.only.split(",")
        tasks = [task for task in tasks if task.id in wanted]
        if len(tasks) != len(wanted):
            print("unknown task id in --only", file=sys.stderr)
            return 2
    registry = approvals.load_registry(ROOT / "secrets" / "approvers.yaml")
    orders = {task.id: condition_order(task.id, conditions, args.order_seed) for task in tasks}

    sh([*COMPOSE["gateway"], "build"])
    run_manifest = manifest(args, tasks, orders)
    args.out.mkdir(parents=True)
    rows = []
    with (
        (args.out / "episodes.jsonl").open("w", encoding="utf-8") as episodes,
        (args.out / "transcripts.jsonl").open("w", encoding="utf-8") as transcripts,
    ):
        for repetition in range(1, args.repetitions + 1):
            for task in tasks:
                for condition in orders[task.id]:
                    base = {
                        "task_id": task.id,
                        "suite": task.suite,
                        "category": task.data["category"],
                        "condition": condition,
                        "routing": "direct" if condition == metrics.BASELINE else "gateway",
                        "repetition": repetition,
                        "model": MODEL,
                        # One seed per repetition, the same in every condition.
                        "seed": args.seed + repetition - 1,
                        "temperature": args.temperature,
                        "think": False,
                        "max_steps": task.max_steps,
                    }
                    row, record = run_episode(task, condition, base, registry)
                    rows.append(row)
                    key = {name: base[name] for name in ("task_id", "condition", "repetition")}
                    episodes.write(json.dumps(row, ensure_ascii=False) + "\n")
                    episodes.flush()
                    transcripts.write(json.dumps({**key, **record}, ensure_ascii=False) + "\n")
                    transcripts.flush()
                    print(
                        f"{task.id} {condition:<14} {row['status']:<9}"
                        f" {row['durations']['total_s']:>7.1f} s",
                        flush=True,
                    )
                    if run_manifest["model_digests"] is None and "relay_models" in row:
                        run_manifest["model_digests"] = row["relay_models"]

    summary = metrics.aggregate(rows)
    done = [row["durations"] for row in rows if row["status"] == "completed"]
    summary["durations_s"] = {
        part: {
            "mean": round(sum(d[part] for d in done) / len(done), 1),
            "max": max(d[part] for d in done),
        }
        for part in ("stack_up_s", "agent_s", "total_s")
        if done
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.out / "manifest.json").write_text(
        json.dumps(run_manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["durations_s"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
