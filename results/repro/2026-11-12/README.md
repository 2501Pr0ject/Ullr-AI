# Reproduction from a fresh clone, 2026-11-12

A reproduction of L1, L2 and the demo, and a functional check of the L3 chain, from a fresh clone of the submission branch. Times are UTC (the night of 11 to 12 November, Paris time). Each command was run once; no step was retried.

## Clone

- Branch `night/submission-v1`, recorded at `b9ca053308c96e6994fbb3692a28d574214afe81` before any reproduction command.
- `git clone --no-hardlinks --single-branch --branch night/submission-v1` of the local repository into a new directory. `HEAD` checked equal to the recorded commit, and `git status --porcelain --untracked-files=all` empty, before the first command.
- The clone generated its own secrets (`make secrets`); none were copied from another working copy.

## Environment

MacBook Air, Apple M2, 16 GB; macOS; Docker Desktop, engine 27.4.0, Compose 2.31.0-desktop.2; uv 0.13.6, Python 3.12.9; Ollama 0.40.13 with `qwen3:8b` (digest `500a1f067a9f…`).

## Journal

| Step | Command | Start | End | Duration (s) | Exit |
|---|---|---|---|---|---|
| 01 | `git clone` (see above) | 23:07:01Z | 23:07:01Z | 0 | 0 |
| 02 | `uv sync` | 23:07:10Z | 23:07:10Z | 0 | 0 |
| 03 | `make lint test` | 23:07:10Z | 23:07:48Z | 38 | 0 |
| 04 | `make secrets` | 23:07:48Z | 23:07:48Z | 0 | 0 |
| 05 | `make attack` | 23:07:54Z | 23:22:03Z | 849 | 0 |
| 06 | `make demo JSON=results/demo-repro/summary.json` | 23:22:38Z | 23:23:58Z | 80 | 0 |
| 07 | `uv run python -m ullr_ai.bench.runner --only A03 --model qwen3:8b --think true --temperature 0 --seed 20261115 --warmup --out results/l3-chain-check-A03` | 23:24:27Z | 23:27:47Z | 200 | 0 |
| 08 | `make test`, clone switched to `b31b75a` | 23:28:02Z | 23:28:37Z | 35 | 0 |
| 09 | `make test`, clone switched to `b8fbb26` | 23:28:37Z | 23:29:11Z | 34 | 2 |

After step 09 the clone was switched back to `b9ca053`.

Between steps 05 and 07, the outputs of steps 05 and 06 were moved out of the clone's working tree, unchanged, so that the L3 runner's clean-tree check (`working_tree_clean`) was not affected. The L3 manifest records `working_tree_clean: true`.

## Results

- **03, L1 at `b9ca053`:** lint clean; 1,872 passed, 2 skipped. Log: `logs/03-lint-test.log`.
- **05, L2 run 3:** 170 records, 170 passed. The report is in [`results/l2/run-3/`](../../l2/run-3/), copied unchanged (SHA-256 checked). Console summary: `logs/05-attack.log`.
- **06, demo:** all four cases completed; same outcomes as described in the README, section 8. Console output: `logs/06-demo.log`; JSON summary: `demo/summary.json`.
- **07, L3 chain check:** one task (A03) under the four conditions, 4/4 episodes completed, no infrastructure failure. This is a check that the L3 chain runs end to end on the final code, not a measurement: one legitimate task, one pass, nothing compared. Files: `l3-chain-check-A03/` (`summary.json`, `status.json`, `episodes.jsonl`, `progress.log`, unchanged).
- **08, L1 at `b31b75a`** (visible-run pre-registration): 1,858 passed, 2 skipped. Log: `logs/08-test-at-b31b75a.log`.
- **09, L1 at `b8fbb26`** (hidden-run pre-registration): 1 failed, 1,857 passed, 2 skipped. The failure is `tests/test_tasks.py::test_every_repository_task_is_valid_and_maps_to_a_tools_seed`: the task inventory test expected the twenty visible tasks only and found H01–H10 as well. It is not a security test; it was corrected on the submission branch (`2ed5e1d`).

## Files not included

The logs of steps 01, 02, 04 and 09, and the L3 check's `manifest.json`, contain absolute paths of the local machine and are not copied here. Their outcomes are given above. The L3 check's `manifest.json` records `code_commit` `b9ca053…`, `working_tree_clean: true`, Ollama 0.40.13, `qwen3:8b` with thinking, temperature 0, seed 20261115 and the same policy hash as the published runs (`sha256:8fdf4b42…`). The L3 check's transcripts and service logs are not copied either.
