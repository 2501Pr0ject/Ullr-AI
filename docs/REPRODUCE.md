# Reproducing the results

What you need, in which order to run it, how long it takes, and how to check that a run is the one it claims to be. Published results are never overwritten: every command below refuses to write into an existing run directory.

## 1. Environment used for the published runs

| Item | Value |
|---|---|
| Machine | MacBook Air, Apple M2, 16 GB |
| OS | macOS (Docker Desktop virtual machine: 8 CPU, about 4 GB of memory) |
| Docker | Docker Desktop, engine 27.4.0, Compose 2.31.0 |
| Python | 3.12 (3.12.9 provisioned by uv); `pyproject.toml` requires `>=3.12,<3.13` |
| uv | 0.13.6 (also pinned in `docker/Dockerfile`) |
| Ollama | 0.40.13 on the host loopback, default context length 4096 tokens (observed with `ollama ps`) |
| Model | `qwen3:8b`, digest `500a1f067a9f…` (full digest in each L3 `manifest.json`) |

The versions actually used are recorded by each run: `summary.versions` in an L2 `report.json`, and `manifest.json` in an L3 directory.

## 2. Prerequisites

| For | You need |
|---|---|
| `uv sync`, `make lint`, `make test` | uv, network access to PyPI. Python 3.12 is provisioned by uv if missing. No Docker, no Ollama. Two tests are skipped: one needs `ULLR_TEST_OLLAMA_URL`, the other (a TCP self-connection) does not run on macOS. |
| `make secrets` | Must run once before anything that uses Docker. Refuses if `secrets/` already holds the files. Writes 8 git-ignored files, including the approver key and registry. |
| `make demo` | Docker. Not Ollama: the model relay is not started. |
| `make attack` (L2) | Docker Desktop, and Ollama on the host at port 11434 with `qwen3:8b`: the relay refuses to start if its upstream is unreachable. Subnets `172.30.0.0/25` and `172.30.1.0/26` must be free. |
| `make smoke`, `make eval-visible`, `make eval-hidden` (L3) | As for L2. `make capability` also needs `llama3.1:8b`. |

**Docker Desktop specifics.** The relay reaches the model at `host.docker.internal`, which `docker/compose.yaml` does not declare in `extra_hosts`; on Docker Engine for Linux it must be added. The agent networks use `com.docker.network.bridge.inhibit_ipv4`; its effect on another platform must be checked with `make attack` before relying on the isolation.

**No Ullr stack may be running.** `make attack` and the L3 runner start by removing their own Compose projects (`ullr`, `ullr-baseline`) with their volumes, and remove them again at the end. `make demo` refuses to start if any `ullr*` project is running; it removes the containers and networks of each case and keeps its volumes (`ullr-demo-*`), which it lists.

## 3. Order of commands and durations

Durations measured on the machine above.

| Step | Command | Duration |
|---|---|---|
| Install | `uv sync` | seconds once the cache is warm |
| L1 | `make lint test` | about 40 s |
| Secrets | `make secrets` | instant |
| Demo | `make demo` | about 1.5 min (four stacks, no model) |
| L2 | `make attack` | about 14–15 min (run 2: 851 s) |
| L3 smoke | `make smoke` | 12 episodes; see `results/m4/smoke/` for the measured episode durations |
| L3 visible | `make eval-visible OUT=<new directory>` | about 4.7 h (80 episodes) |
| L3 hidden | `make eval-hidden OUT=<new directory>` | about 1.6 h (40 episodes) |

L3 durations and outcomes depend on the hardware: a model request is limited to 600 s and an episode to 900 s, and a timeout is scored as observed, never rerun. A faster or slower machine can change which episodes time out.

## 4. Replaying without overwriting

- **L2.** `make attack` writes to `results/l2/latest/` and refuses if a report is already there. Rename the directory afterwards to keep it. The published runs are `results/l2/run-1/`, `run-2/` and `run-3/`.
- **L3 visible.** `make eval-visible` without `OUT` targets `results/l3/visible-1/`, the published run, and the runner refuses because the directory exists. Use `make eval-visible OUT=results/l3/visible-replay-1`.
- **L3 hidden.** `make eval-hidden OUT=results/l3/hidden-replay-1`. `OUT` is required. This is the command of the pre-registered hidden run (`docs/EVALUATION_PLAN.md` §11), with the same model, thinking, temperature, seed, order seed and warm-up.
- A replay on a later commit is not the published run: the manifest records the commit, and only `b31b75a` (visible) and `b8fbb26` (hidden) are the pre-registered code states. Their executable code is identical to each other; later commits add the secondary-measures script, the demo, attacks, tests and documentation, not changes to the Gateway, the Tools service, the policy, the agent prompt or its tool definitions.
- There is no `make eval` target. Run the layers one by one, as above.

## 5. Checking a run

**Hidden-set commitment.** From `tasks/hidden/`:

```sh
sed -n '/^```$/,/^```$/p' ../../docs/HIDDEN_SET_COMMITMENT.md | grep -v '```' | shasum -a 256 -c
```

All eleven lines must read `OK`.

**L3 manifest.** In `results/l3/<run>/manifest.json`, check:
- `code_commit` and `working_tree_clean: true`;
- `policy_hash` against `shasum -a 256 policies/default.yaml` at that commit;
- `model_digests` against `ollama list` (the hidden manifest also lists `llama3.1:8b`, copied from a baseline relay that allows it; see its README);
- `system_prompt_hash` and `tool_definitions_hash`, `temperature`, `seed`, `think`, `order_seed`, `warmup`;
- `ollama_version`.

`tasks_directory` is the absolute path of the machine that ran it.

**L2 report.** `summary.versions` records the commit, `git_dirty` (result files excluded), the image id and the Docker and Compose versions. Run 1 was executed on a modified tree (`git_dirty: true`).

**Bypass cross-check.** For each protected L3 episode, `bypass.unbacked` lists Tools executions without exactly one valid Gateway action; it must be empty. The check is `src/ullr_ai/bench/metrics.py`, `unbacked_executions`.

## 6. Reproduction performed

A reproduction from a fresh clone of the final branch is recorded in [`results/repro/2026-11-12/`](../results/repro/2026-11-12/): commands, exit codes and durations.
