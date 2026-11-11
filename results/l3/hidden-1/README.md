# L3 run on the hidden set

The pre-registered hidden-set run of `docs/EVALUATION_PLAN.md` v1.7, §11 (pre-registration commit `b8fbb26`). The code commit recorded in `manifest.json` is the same commit, with a clean working tree.

- 10 hidden tasks (H01–H10) under 4 conditions, 1 repetition, 40 episodes.
- qwen3:8b with `think: true`, temperature 0, seed 20261115, order seed 1, warm-up, 600 s model request limit, 900 s episode limit.
- 40 of 40 episodes completed. No infrastructure failure and no rerun: `reruns.jsonl` and `rerun_transcripts.jsonl` are empty.
- The ten task files match the SHA-256 digests in `docs/HIDDEN_SET_COMMITMENT.md`, as does `tasks/hidden/HIDDEN_SET.md`, added after the run.

## Files

Raw outputs written by the runner, unedited:

- `manifest.json`, `summary.json`, `status.json`, `progress.log`
- `episodes.jsonl`, `transcripts.jsonl`, `reruns.jsonl`, `rerun_transcripts.jsonl`
- `logs/`: the service logs of each episode's stack

Files added after the run:

- `console.log`: the runner's console output, written outside the repository during the run so that the manifest's working-tree check was not affected, then moved here when the run ended. The last line, `exit=0`, was appended by the shell, not by the runner.
- `ollama-ps.txt`: the output of `ollama ps`, captured by the operator after the run ended. According to the operator, it was captured just after the end, while the model was still loaded by the run's last request. The file's modification time is 2026-11-11T15:53:24Z; the run's final status is timestamped 2026-11-11T15:46:01Z.
- `README.md`: this file.

## Observations recorded without changing any row

- **No timeout.** No model request reached the 600 s limit, and every episode ended with a final answer.
- **Model digests in the manifest.** `model_digests` is copied from the relay of the first episode (H01, baseline). The baseline relay also allows `llama3.1:8b`, so that model is listed. Every episode's request used `qwen3:8b`, digest `500a1f067a9f…`.
- **Image id.** The image id differs from the visible run's, although the image's build inputs (`src/`, `policies/`, `attacks/`, `pyproject.toml`, `uv.lock`, `LICENSE`, `docker/`) are unchanged since `b31b75a`.
- **Service logs.** The per-episode files in `logs/` hold only the relay's start-up line. The other services logged nothing.
