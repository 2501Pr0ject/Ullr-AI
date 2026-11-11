.PHONY: lint test secrets build up down attack attack-quick smoke capability eval-visible \
	eval-hidden demo

COMPOSE = docker compose -f docker/compose.yaml

lint:
	uv run ruff check .
	uv run ruff format --check .

test:
	uv run pytest

# Local secrets for the Docker stack (git-ignored). Fails if they already exist.
secrets:
	uv run python scripts/gen_secrets.py

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v --remove-orphans

# L2: scripted attacker inside the agent container, crash cases, baseline control.
# Writes report.json, raw_records.jsonl and tools_counters.json to results/l2/latest/
# and refuses to run if a report is already there. Needs `make secrets` first,
# Docker and, for the relay check, Ollama on the host loopback with the
# allow-listed model.
attack:
	uv run python -m attacks.driver

attack-quick:
	uv run python -m attacks.driver --quick

# Demo, no model: a scripted agent replays task B10 through the real stacks
# (baseline, Gateway + AP-provenance, Gateway + AP-oracle), after a 900.00 EUR
# refund the policy denies. Needs `make secrets` and Docker, not Ollama. Writes a
# JSON summary to results/demo/<time>/summary.json, or to JSON=<path>.
demo:
	uv run python -m ullr_ai.demo.run $(if $(JSON),--json $(JSON))

# Smoke of the L3 harness: 3 tasks, 1 repetition, all conditions. An integration
# run, not an evaluation. Prints the measured duration per episode.
smoke:
	uv run python -m ullr_ai.bench.runner --only A03,A09,B01 \
		--out results/m4/smoke-$$(date +%Y%m%dT%H%M%S)

# Capability check: suite A, baseline routing only, three model configurations.
SUITE_A = A01,A02,A03,A04,A05,A06,A07,A08,A09,A10
CAPABILITY = uv run python -m ullr_ai.bench.runner --only $(SUITE_A) --conditions baseline --warmup
capability:
	$(CAPABILITY) --model qwen3:8b --think false --out results/m4/capability/qwen3-8b-think-false
	$(CAPABILITY) --model qwen3:8b --think true --out results/m4/capability/qwen3-8b-think-true
	$(CAPABILITY) --model llama3.1:8b --think not_applicable \
		--out results/m4/capability/llama3.1-8b

# L3, visible tasks: one deterministic pass, four conditions, pre-registered
# configuration (EVALUATION_PLAN.md section 6). Refuses to overwrite a run: the
# default output, results/l3/visible-1, holds the published run, so a replay
# needs OUT=<new directory>.
VISIBLE = A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,B01,B02,B03,B04,B05,B06,B07,B08,B09,B10
eval-visible:
	uv run python -m ullr_ai.bench.runner --only $(VISIBLE) --model qwen3:8b --think true \
		--temperature 0 --seed 20261115 --warmup --out $(or $(OUT),results/l3/visible-1)

# L3, hidden tasks: the command of the pre-registered hidden run (EVALUATION_PLAN.md
# section 11), with the same configuration as the visible run. OUT is required and
# must be a new directory: the published run, results/l3/hidden-1, is never
# overwritten (the runner also refuses any existing directory).
HIDDEN = H01,H02,H03,H04,H05,H06,H07,H08,H09,H10
eval-hidden:
	@test -n "$(OUT)" || { echo "eval-hidden: OUT=<new directory> is required" >&2; exit 2; }
	uv run python -m ullr_ai.bench.runner --only $(HIDDEN) --model qwen3:8b --think true \
		--temperature 0 --seed 20261115 --warmup --out $(OUT)
