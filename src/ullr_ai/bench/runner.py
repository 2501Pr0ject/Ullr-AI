"""L3 runner: the same agent on every task, with and without the Gateway.

    uv run python -m ullr_ai.bench.runner --tasks tasks --out results/l3/NAME \\
        [--only A03,A09,B01] [--conditions baseline,AP-rubber,...] [--seed N]
        [--model NAME] [--think true|false|not_applicable] [--warmup]

Runs on the host and drives the two Compose projects, as the L2 driver does.
Every episode starts from a stack created for it and removed after it, in both
routings: no database, volume, session or log survives from one episode or
condition to the next. Outcomes are read from the Tools service only.

Written to the output directory, which must not exist yet:
- ``episodes.jsonl``: one row per episode, skipped and failed ones included;
- ``transcripts.jsonl``: the agent's transcript and the approver's log;
- ``reruns.jsonl``, ``rerun_transcripts.jsonl``: reruns, see below;
- ``logs/``: the service logs of every episode's stack, taken before removal;
- ``progress.log`` and ``status.json``: what has run so far, and whether the
  run finished;
- ``summary.json``: the metrics of EVALUATION_PLAN.md section 7;
- ``manifest.json``: what is needed to tell which run this was.

Rerun rule (EVALUATION_PLAN.md section 6). An episode is run again only if it
failed for an infrastructure reason before the agent process was started, so
before any model request could be made. The failed row stays in
``episodes.jsonl``; each rerun goes to ``reruns.jsonl`` with ``rerun_of`` and
its attempt number, failed ones included. The summary uses a completed rerun
in place of its failed original. Nothing is ever rerun for its outcome.
"""

import argparse
import hashlib
import json
import random
import subprocess
import sys
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
MAX_RERUNS = 2  # per episode, only under the rerun rule


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

    def up(self, attempts: int = 3) -> int:
        """Create the stack; returns the number of attempts it took.

        Two services that share a new SQLite volume can collide while creating
        it, and the loser refuses to start. An episode must not run on a stack
        with a missing service, so the stack is checked and recreated if needed.
        """
        for attempt in range(1, attempts + 1):
            self.down()
            sh([*self._compose, "up", "-d", "--wait"])
            time.sleep(2.0)  # a service that refuses to start exits within this
            listing = sh([*self._compose, "ps", "-a", "--format", "{{.Service}} {{.State}}"])
            if not not_running(listing):
                self.controller("wait")
                return attempt
        raise RuntimeError(
            f"services not running after {attempts} attempts: {not_running(listing)}"
        )

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

    def save_logs(self, path: Path) -> None:
        """Service logs of this stack, kept before it is removed. Best effort."""
        try:
            text = sh([*self._compose, "logs", "--no-color", "--timestamps"], timeout=120)
        except (RuntimeError, subprocess.SubprocessError) as exc:
            text = f"logs not available: {type(exc).__name__}\n"
        path.write_text(text, encoding="utf-8")

    def relay_models(self) -> dict[str, str]:
        """Model digests the relay reported when it started."""
        for line in sh([*self._compose, "logs", "--no-log-prefix", "llm-relay"]).splitlines():
            if '"relay_ready"' in line:
                return json.loads(line)["models"]
        raise RuntimeError("the relay did not report its models")


def not_running(listing: str) -> list[str]:
    """Services of a ``compose ps`` listing (``service state`` per line) that are not running."""
    return [
        line.split()[0]
        for line in listing.splitlines()
        if line.strip() and line.split()[-1] != "running"
    ]


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


def eligible_for_rerun(row: dict[str, Any]) -> bool:
    """An infrastructure failure before the agent process started, and nothing else."""
    return row["status"] == "error" and row.get("model_requested") is False


def run_episode(
    task: Task,
    condition: str,
    base: dict[str, Any],
    registry: dict[str, str],
    log_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """One episode. Returns ``(row, transcript record)``.

    ``model_requested`` in the row is false only if the agent process was never
    started; once it has started, a model request may have been made.
    """
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
    model_requested = False
    try:
        attempts = stack.up()
        timings["stack_up_s"] = round(time.monotonic() - started, 1)  # includes a prior removal
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
            "think": base["think"] if type(base["think"]) is bool else None,
            "time_limit": EPISODE_TIME_LIMIT,
        }
        agent_started = time.monotonic()
        model_requested = True
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
        timings["agent_s"] = round(time.monotonic() - agent_started, 1)  # the whole process
        # From the first model request to the end of the episode, measured by the agent.
        timings["agent_episode_s"] = round(transcript["agent_ms"] / 1000, 1)

        gateway_state = None
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
        row["stack_attempts"] = attempts
        row["relay_models"] = stack.relay_models()
        row["effective_request"] = transcript["request"]  # model, think and options as sent
        row["prompt_hashes_match"] = (
            transcript["system_prompt_hash"] == prompt.system_prompt_hash()
            and transcript["tool_definitions_hash"] == tools.definitions_hash()
        )
        record = {"transcript": transcript, "approver_log": approver_log, "snapshot": snapshot}
    except (RuntimeError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        row = {**base, "status": "error", "error": f"{type(exc).__name__}: {exc}"[-500:]}
        record = {"approver_log": approver_log}
    finally:
        if approver is not None:
            approver.kill()
        if log_path is not None:
            stack.save_logs(log_path)
        teardown_started = time.monotonic()
        try:
            stack.down()
        except (RuntimeError, subprocess.SubprocessError):
            print("stack could not be removed", file=sys.stderr)
    timings["teardown_s"] = round(time.monotonic() - teardown_started, 1)
    timings["total_s"] = round(time.monotonic() - started, 1)
    row["durations"] = timings
    row["model_requested"] = model_requested
    return row, record


def effective_rows(
    rows: list[dict[str, Any]], reruns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Rows counted in the summary: each original, or the completed rerun that replaces it.

    A failed rerun is never counted; an original without a completed rerun is
    counted as it is (an error row, so not a completed episode).
    """
    replacement = {}
    for rerun in reruns:
        if rerun["status"] == "completed":
            key = tuple(rerun["rerun_of"][k] for k in ("task_id", "condition", "repetition"))
            replacement.setdefault(key, rerun)
    return [
        replacement.get((row["task_id"], row["condition"], row["repetition"]), row)
        if eligible_for_rerun(row)
        else row
        for row in rows
    ]


def write_status(out: Path, state: str, done: int, total: int) -> None:
    status = {
        "state": state,
        "episodes_done": done,
        "episodes_planned": total,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (out / "status.json").write_text(json.dumps(status) + "\n", encoding="utf-8")


def think_setting(value: str) -> bool | str:
    """``true``/``false`` as booleans; ``not_applicable`` stays a word and is never sent."""
    return {"true": True, "false": False}.get(value, "not_applicable")


def warm_up(model: str, think: bool | str, args: argparse.Namespace) -> dict[str, Any]:
    """One uncounted request, so that loading the model is not charged to an episode.

    Sent from the host to Ollama on the loopback address, with the settings of
    the run. Its duration is recorded in the manifest and nowhere else.
    """
    request: dict[str, Any] = {
        "model": model,
        "stream": False,
        "messages": [{"role": "user", "content": "Reply with the single word OK."}],
        "options": {"temperature": args.temperature, "seed": args.seed},
    }
    if type(think) is bool:
        request["think"] = think
    started = time.monotonic()
    response = httpx.post(OLLAMA + "/api/chat", json=request, timeout=600)
    return {
        "http_status": response.status_code,
        "seconds": round(time.monotonic() - started, 1),
    }


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
        "model": args.model,
        "model_digests": None,  # filled from the relay's own start-up report
        "policy_hash": load_policy(ROOT / "policies" / "default.yaml").policy_hash,
        "canon_version": CANON_VERSION,
        "system_prompt_hash": prompt.system_prompt_hash(),
        "tool_definitions_hash": tools.definitions_hash(),
        "temperature": args.temperature,
        "seed": args.seed,
        "think": think_setting(args.think),
        "warmup": None,  # filled when --warmup is given
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
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--think", choices=["true", "false", "not_applicable"], default="false")
    parser.add_argument("--warmup", action="store_true", help="one uncounted model request first")
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
    if args.warmup:
        run_manifest["warmup"] = warm_up(args.model, think_setting(args.think), args)
    args.out.mkdir(parents=True)
    (args.out / "logs").mkdir()
    total = args.repetitions * sum(len(orders[task.id]) for task in tasks)
    write_status(args.out, "running", 0, total)
    rows = []
    reruns: list[dict[str, Any]] = []
    with (
        (args.out / "episodes.jsonl").open("w", encoding="utf-8") as episodes,
        (args.out / "transcripts.jsonl").open("w", encoding="utf-8") as transcripts,
        (args.out / "reruns.jsonl").open("w", encoding="utf-8") as rerun_rows,
        (args.out / "rerun_transcripts.jsonl").open("w", encoding="utf-8") as rerun_records,
        (args.out / "progress.log").open("w", encoding="utf-8") as progress,
    ):

        def report(line: str) -> None:
            print(line, flush=True)
            progress.write(line + "\n")
            progress.flush()

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
                        "model": args.model,
                        # One seed per repetition, the same in every condition.
                        "seed": args.seed + repetition - 1,
                        "temperature": args.temperature,
                        "think": think_setting(args.think),
                        "max_steps": task.max_steps,
                        # The first episode after a model change, even after a warm-up.
                        "first_of_configuration": not rows,
                    }
                    key = {name: base[name] for name in ("task_id", "condition", "repetition")}
                    name = f"{task.id}_{condition}_r{repetition}"
                    row, record = run_episode(
                        task, condition, base, registry, args.out / "logs" / f"{name}.log"
                    )
                    rows.append(row)
                    episodes.write(json.dumps(row, ensure_ascii=False) + "\n")
                    episodes.flush()
                    transcripts.write(json.dumps({**key, **record}, ensure_ascii=False) + "\n")
                    transcripts.flush()
                    report(
                        f"{task.id} {condition:<14} {row['status']:<9}"
                        f" {row['durations']['total_s']:>7.1f} s"
                    )
                    attempt, last = 0, row
                    while eligible_for_rerun(last) and attempt < MAX_RERUNS:
                        attempt += 1
                        last, record = run_episode(
                            task,
                            condition,
                            base,
                            registry,
                            args.out / "logs" / f"{name}_rerun{attempt}.log",
                        )
                        last |= {"rerun_of": key, "rerun_attempt": attempt}
                        reruns.append(last)
                        rerun_rows.write(json.dumps(last, ensure_ascii=False) + "\n")
                        rerun_rows.flush()
                        rerun_records.write(
                            json.dumps({**key, "rerun_attempt": attempt, **record}) + "\n"
                        )
                        rerun_records.flush()
                        report(f"{task.id} {condition:<14} rerun {attempt}: {last['status']}")
                    if run_manifest["model_digests"] is None and "relay_models" in last:
                        run_manifest["model_digests"] = last["relay_models"]
                    write_status(args.out, "running", len(rows), total)

    counted = effective_rows(rows, reruns)
    summary = metrics.aggregate(counted)
    summary["infrastructure"] = {
        "episodes": len(rows),
        "failed_originals": [
            {"task_id": r["task_id"], "condition": r["condition"], "error": r.get("error")}
            for r in rows
            if r["status"] == "error"
        ],
        "eligible_for_rerun": sum(1 for r in rows if eligible_for_rerun(r)),
        "reruns": len(reruns),
        "valid_reruns": sum(1 for r in reruns if r["status"] == "completed"),
        "failed_reruns": sum(1 for r in reruns if r["status"] != "completed"),
        "counted_episodes": len(counted),
    }
    done = [row["durations"] for row in counted if row["status"] == "completed"]
    summary["durations_s"] = {
        part: {
            "mean": round(sum(d[part] for d in done) / len(done), 1),
            "max": max(d[part] for d in done),
        }
        for part in ("stack_up_s", "agent_s", "agent_episode_s", "teardown_s", "total_s")
        if done
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.out / "manifest.json").write_text(
        json.dumps(run_manifest, indent=2) + "\n", encoding="utf-8"
    )
    write_status(args.out, "completed", len(rows), total)
    print(json.dumps(summary["durations_s"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
