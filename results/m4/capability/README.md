# M4 capability check

Question: does the agent use its tools well enough for L3 to measure protection and not inaction? This is **not an L3 evaluation**: suite A only (the 10 visible legitimate tasks), baseline routing only (no Gateway, no approver), temperature 0, seed 20261115, one pass per configuration.

Configurations, one directory each, as written by the runs:

| Directory | Model | Think |
|---|---|---|
| `qwen3-8b-think-false/` | `qwen3:8b` | sent as `false` |
| `qwen3-8b-think-true/` | `qwen3:8b` | sent as `true` |
| `llama3.1-8b/` | `llama3.1:8b` | not applicable: the model has no thinking capability and the field was not sent |

Each directory holds `episodes.jsonl`, `transcripts.jsonl`, `manifest.json` (model digest, options, warm-up) and the run's own `summary.json`. All three received the same task files (hashes in the manifests), each episode on a stack created for it.

Other files:

- `summary.json`: the comparison, built by `scripts/capability_summary.py`.
- `final_answers.jsonl`: each final answer with the tool calls and normalized replies of its episode.
- `hallucination_annotations.json`: manual labels, one per episode, with the reason. Not computed.
- `reruns/`: three episodes run again, see below.
- `reruns-void/`: a first attempt at those reruns, not used, see below.

## Harness failures and reruns

Three episodes failed before any model request (`qwen3-8b-think-false` A01 and A08, `qwen3-8b-think-true` A04). Cause, reproduced afterwards: on a new volume the two Tools processes can collide while creating the SQLite database, and the loser refuses to start ("database is locked"); observed once in 14 start-ups of the baseline stack. The original rows are kept as they were, with status `error`.

A first rerun (`reruns-void/`) hit the same collision on the other Tools process: two of its three episodes got no reply from the Tools service. It is kept for the record and used nowhere.

The runner was then changed to check that every service is running before an episode and to recreate the stack otherwise (commit `58f494b`; the three original runs are on `67f8f20`, which differs by that change only). `reruns/` holds the three episodes run with it. `summary.json` uses them in place of the failed rows and marks them `rerun`.

## Reading the durations

Agent time runs from the first model request to the end of the episode. Each configuration was preceded by one uncounted warm-up request; its first episode is still flagged. In `qwen3-8b-think-true`, A07 never answered: its single model request ended at the 600 s limit. That episode counts as inaction and its 600 s is in the mean.
