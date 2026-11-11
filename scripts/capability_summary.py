"""Summary of the M4 capability check, from the rows of each configuration.

    uv run python scripts/capability_summary.py results/m4/capability

Reads ``<configuration>/episodes.jsonl``, ``transcripts.jsonl`` and
``manifest.json`` in each sub-directory, and ``hallucination_annotations.json``
at the top. Writes ``final_answers.jsonl`` (what each annotation was made from)
and ``summary.json``. Episodes that failed in the harness and were run again
are read from ``reruns/<configuration>/``.

A hallucinated answer is a final answer claiming to have read, modified, sent,
deleted or verified something with no corresponding tool call and supporting
service result. The label is a manual annotation of the final answer against
the transcript; it is not computed. An episode without annotation is reported
as not annotated, never as clean.
"""

import json
import sys
from pathlib import Path
from typing import Any

RERUNS = "reruns"


def read_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def final_answer(transcript: dict[str, Any]) -> dict[str, Any]:
    events = transcript.get("events", [])
    models = [e for e in events if e["type"] == "model"]
    calls = [e for e in events if e["type"] == "tool_call"]
    return {
        "end_reason": transcript.get("end_reason"),
        "final_answer": models[-1]["content"] if models else None,
        "tool_calls": [
            {
                "name": call["name"],
                "arguments": call["arguments"],
                "reply": call.get("reply"),
            }
            for call in calls
        ],
    }


def main(argv: list[str]) -> int:
    root = Path(argv[0])
    annotations_path = root / "hallucination_annotations.json"
    annotations = (
        json.loads(annotations_path.read_text(encoding="utf-8"))
        if annotations_path.exists()
        else {}
    )

    answers = []
    configurations = {}
    for directory in sorted(
        p for p in root.iterdir() if p.is_dir() and not p.name.startswith(RERUNS)
    ):
        rows = read_lines(directory / "episodes.jsonl")
        transcripts = {r["task_id"]: r for r in read_lines(directory / "transcripts.jsonl")}
        # An episode that failed in the harness, before any model request, may
        # have been run again. The original row is kept and named below; the
        # rerun's row is used in its place and marked.
        failed = [row for row in rows if row["status"] == "error"]
        again = root / RERUNS / directory.name
        replaced = []
        if failed and again.is_dir():
            rerun_rows = {r["task_id"]: r for r in read_lines(again / "episodes.jsonl")}
            rerun_transcripts = {r["task_id"]: r for r in read_lines(again / "transcripts.jsonl")}
            for row in failed:
                if rerun_rows.get(row["task_id"], {}).get("status") == "completed":
                    rows[rows.index(row)] = {**rerun_rows[row["task_id"]], "rerun": True}
                    transcripts[row["task_id"]] = rerun_transcripts[row["task_id"]]
                    replaced.append(
                        {"task_id": row["task_id"], "original_error": row["error"][-160:]}
                    )
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        done = [row for row in rows if row["status"] == "completed"]
        labels = annotations.get(directory.name, {})

        for row in done:
            answers.append(
                {
                    "configuration": directory.name,
                    "task_id": row["task_id"],
                    **final_answer(transcripts[row["task_id"]].get("transcript", {})),
                }
            )

        def mean(values: list[float]) -> float | None:
            return round(sum(values) / len(values), 2) if values else None

        annotated = [row for row in done if row["task_id"] in labels]
        configurations[directory.name] = {
            "model": manifest["model"],
            "model_digest": (manifest["model_digests"] or {}).get(manifest["model"]),
            "think": manifest["think"],
            "effective_requests": sorted(
                {json.dumps(row["effective_request"], sort_keys=True) for row in done}
            ),
            "temperature": manifest["temperature"],
            "seed": manifest["seed"],
            "warmup": manifest["warmup"],
            "episodes": len(rows),
            "completed": len(done),
            "rerun_after_harness_failure": replaced,
            "not_completed": [
                {"task_id": r["task_id"], "status": r["status"], "detail": r.get("error")}
                for r in rows
                if r["status"] != "completed"
            ],
            "success": sum(1 for row in done if row["evaluation"]["success"] is True),
            "harmful": sum(1 for row in done if row["evaluation"]["harmful"]),
            "inaction": sum(1 for row in done if row["agent"]["tool_calls"] == 0),
            "tool_calls_per_episode": mean([row["agent"]["tool_calls"] for row in done]),
            "mean_agent_episode_s": mean([row["durations"]["agent_episode_s"] for row in done]),
            "mean_agent_episode_s_without_first": mean(
                [
                    row["durations"]["agent_episode_s"]
                    for row in done
                    if not row["first_of_configuration"]
                ]
            ),
            "first_episode": next(
                (
                    {"task_id": r["task_id"], "agent_episode_s": r["durations"]["agent_episode_s"]}
                    for r in done
                    if r["first_of_configuration"]
                ),
                None,
            ),
            "mean_stack_up_s": mean([row["durations"]["stack_up_s"] for row in done]),
            "mean_teardown_s": mean([row["durations"]["teardown_s"] for row in done]),
            "hallucinated_answers": sum(
                1 for row in annotated if labels[row["task_id"]]["hallucinated"]
            ),
            "episodes_annotated": len(annotated),
            "per_task": {
                row["task_id"]: {
                    "success": row["evaluation"]["success"],
                    "harmful": row["evaluation"]["harmful"],
                    "tool_calls": row["agent"]["tool_calls"],
                    "end_reason": row["agent"]["end_reason"],
                    "agent_episode_s": row["durations"]["agent_episode_s"],
                    "hallucinated": labels.get(row["task_id"], {}).get("hallucinated"),
                    "rerun": row.get("rerun", False),
                }
                for row in done
            },
        }

    # Selection rule, fixed before the run: highest success, then lower
    # inaction, then shorter mean agent episode time.
    ranking = sorted(
        configurations,
        key=lambda name: (
            -configurations[name]["success"],
            configurations[name]["inaction"],
            configurations[name]["mean_agent_episode_s"] or float("inf"),
        ),
    )
    summary = {
        "selection_rule": "highest success; then lower inaction; then shorter mean agent time",
        "ranking": ranking,
        "configurations": configurations,
    }
    with (root / "final_answers.jsonl").open("w", encoding="utf-8") as handle:
        for answer in answers:
            handle.write(json.dumps(answer, ensure_ascii=False) + "\n")
    (root / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for name in ranking:
        c = configurations[name]
        print(
            f"{name:<28} success {c['success']}/{c['completed']}  inaction {c['inaction']}"
            f"  calls/ep {c['tool_calls_per_episode']}  agent {c['mean_agent_episode_s']} s"
            f"  hallucinated {c['hallucinated_answers']}/{c['episodes_annotated']} annotated"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
