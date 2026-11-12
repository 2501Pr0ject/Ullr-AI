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

**Warning: the L2 and L3 commands delete Docker volumes.** `make attack`, `make attack-quick`, `make smoke`, `make eval-visible`, `make eval-hidden` and `make down` run `docker compose down -v --remove-orphans` on the Compose projects `ullr` and `ullr-baseline`. `make attack` does it before starting and at the end; the L3 runner does it before and after every episode. This deletes the named volumes `ullr_gateway_db`, `ullr_tools_state`, `ullr_episode_1`, `ullr_episode_2`, `ullr_episode_3` and `ullr-baseline_tools_state`, whether or not a container is running: checking that no container is running is not enough. Before running these commands, list the volumes of both projects and make sure none holds data you want to keep:

```sh
docker volume ls --filter label=com.docker.compose.project=ullr
docker volume ls --filter label=com.docker.compose.project=ullr-baseline
```

The project names come from the `name:` key of `docker/compose.yaml` and `docker/baseline/compose.yaml`. A `COMPOSE_PROJECT_NAME` variable set in your shell takes precedence over that key and would redirect the deletion to another project: leave it unset. If `make attack` stops on an error, it leaves its stack in place, and the next run removes it.

`make demo` deletes no volume. It refuses to start if any `ullr*` project has a running container. Each case runs in its own project, `ullr-demo-<time>-<case>`, whose containers and networks are removed at the end of the case. Its volumes (`ullr-demo-*`, 16 per run) are kept and listed in the summary; nothing in the repository removes them.

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
- **L3 hidden.** `make eval-hidden OUT=results/l3/hidden-replay-1`. `OUT` is required. It runs the runner with the configuration pre-registered in `docs/EVALUATION_PLAN.md` §11: same model, thinking, temperature, seed, order seed and warm-up as the visible run.
- There is no `make eval` target. Run the layers one by one, as above.

### Historical provenance and replay from HEAD

These are two different things. Each L3 manifest records the commit actually executed (`code_commit`) and `working_tree_clean`, so a replay can always be told apart from the published run.

**Historical provenance.** These are the exact code states of the published runs.

- **Visible run** (`results/l3/visible-1/`): executed on `b31b75a`. At that commit, `make eval-visible` runs:
  ```sh
  uv run python -m ullr_ai.bench.runner --only A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,B01,B02,B03,B04,B05,B06,B07,B08,B09,B10 --model qwen3:8b --think true --temperature 0 --seed 20261115 --warmup --out results/l3/visible-1
  ```
- **Hidden run** (`results/l3/hidden-1/`): executed on `b8fbb26`, as recorded by its manifest. At that commit there is no `make eval-hidden` target. The command typed for the run was not kept: it is not in the repository, the manifest records arguments and not a command line, and neither `console.log` nor `progress.log` contains it. The command below is therefore a **reconstruction**, not the original command:
  ```sh
  uv run python -m ullr_ai.bench.runner --only H01,H02,H03,H04,H05,H06,H07,H08,H09,H10 --model qwen3:8b --think true --temperature 0 --seed 20261115 --warmup --out results/l3/hidden-1
  ```
  - **Checked against the runner at `b8fbb26`.** Its parser accepts every option used here: `--only`, `--model`, `--think` (`true`, `false` or `not_applicable`), `--temperature`, `--seed` and `--warmup`, and `--out`, which is required.
  - **Checked against the manifest.**
    - Tasks: H01–H10.
    - Conditions: the four conditions, in each task's recorded order.
    - Model, thinking, temperature and seed: `qwen3:8b`, `think: true`, temperature 0, seed 20261115.
    - Order seed, repetitions and warm-up: order seed 1, one repetition, and a warm-up request.
    - Tasks directory: the repository's `tasks/`.
    - Commit: `code_commit` `b8fbb26`, `working_tree_clean: true`.
  - **Checked against the other provenance.** The configuration also agrees with `docs/EVALUATION_PLAN.md` §11 at `b8fbb26` and with `results/l3/hidden-1/README.md`.
  - **Limits.**
    - Temperature, seed, order seed, repetitions, conditions and tasks directory equal the runner's defaults, so whether they were given explicitly cannot be known. The effective values are the same either way.
    - The output directory is not in the manifest; it is taken from where the run is stored.
    - How the runner was invoked (`uv run` or otherwise) is not recorded.
    - The environment (machine, Docker, Ollama and model digest) is not part of the command; it is recorded in the manifest.
- To replay on the historical code, check out the commit, generate secrets (`make secrets`), and give the runner a new `--out` directory.
- `git diff --name-only b31b75a b8fbb26` lists, apart from `results/` and `docs/`, only the ten hidden task files `tasks/hidden/H01.yaml`–`H10.yaml`.

**Replay from HEAD.** This uses the current runner. It is a reproduction, not the published run.

- `git diff --name-only b8fbb26 HEAD` lists the following paths, apart from `results/`, `docs/` and `README.md`:
  - `Makefile`;
  - `attacks/driver.py` and `attacks/run.py`;
  - `scripts/secondary_measures.py`;
  - `src/ullr_ai/demo/` (new);
  - `tasks/hidden/HIDDEN_SET.md`;
  - `tests/test_attacker.py`, `tests/test_demo.py` and `tests/test_tasks.py`.
- Restricted to the L3 runner and harness (`src/ullr_ai/bench/`), the agent (`src/ullr_ai/agent/`), the Gateway, the Tools service, the approver, the rest of `src/`, `policies/`, `docker/`, `pyproject.toml`, `uv.lock` and the task files (`*.yaml`), the same command shows no difference.
- In the `Makefile`, the `eval-visible` command is unchanged except that `OUT` can replace the default output directory. `eval-hidden` and `demo` are new.
- The runner imports neither `attacks/` nor `src/ullr_ai/demo/`.
- `tasks/hidden/HIDDEN_SET.md` is not a task file: the loader reads `*.yaml` only.
- The Docker image copies `src/` and `attacks/`, so an image built at HEAD contains the changed attacker and the demo package. L3 does not execute them, but the image id differs; it already differed between the two published runs.
- **Visible tasks from HEAD.** Between `b31b75a` and HEAD, the code differences are the ones listed above, plus the ten hidden task files. The loader reads every `*.yaml` under `tasks/`, so at HEAD it also loads and validates H01–H10 before `--only` selects the visible tasks. The visible task files themselves are unchanged.

So, within what was checked, `make eval-visible OUT=<new directory>` and `make eval-hidden OUT=<new directory>` at HEAD replay the published episodes with the current runner. They use the same configuration, and the paths listed above are unchanged. This is a reproduction, not the historical provenance. Its manifest records the HEAD commit, and the manifest's `code_commit` is the reference for the commit actually executed. Outcomes also depend on the machine and the model server (section 3).

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

## 6. Demo: what is and is not checked

`make demo` (`src/ullr_ai/demo/run.py`) runs a scripted agent through the real stacks.

**What it reads back.** For each case:
- each step's reply, as the agent received it;
- the Gateway's recorded state (actions, statuses, stored approvals) and its audit-chain check (`audit.verify_chain`, through the admin `state` route);
- the approver's own log;
- the Tools service's execution log and final state.

It then runs the bypass cross-check `metrics.unbacked_executions` and the B10 ground truth on that state. Nothing shown is written in advance.

**Three known limits.** None changes a recorded result, and the demo code is not modified before the deadline.

1. **Pairing of steps with Gateway actions.** `attribute()` pairs each step with the next action of the session, in order, and treats a step with HTTP 400 as having created none. Its docstring overstates this. A proposal can also create no action with another status (401, 404, 409, 502, or 500 before commit). And for an action that needed approval, the step's status is the one of the execute call, made after the action was created. Most such mismatches change the count, and the function then refuses the attribution and the case is reported as an error. In theory, two opposite errors in the same case, on the same tool and resource, could compensate and produce a silent mis-pairing. The recorded runs contain no HTTP 400 and no count mismatch.
2. **Audit checked before revocation.** The audit chain shown is the one verified when the Gateway state was read: after the agent and the approver stopped, before the Tools snapshot and before the session is revoked. It therefore does not include the `SESSION_REVOKED` event, and the chain is not checked again after the revocation.
3. **Settling timeout not reported.** The demo waits up to 60 seconds for actions to leave `EXECUTING` or `UNKNOWN`. If that delay expires with an action still open, the case is still reported as completed; the open status appears only in that step's line, with no explicit warning. This did not happen in any recorded run.

## 7. Reproduction performed

A reproduction from a fresh clone of the final branch is recorded in [`results/repro/2026-11-12/`](../results/repro/2026-11-12/): commands, exit codes and durations.
