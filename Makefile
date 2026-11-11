.PHONY: lint test secrets build up down attack attack-quick smoke capability

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
# Writes results/l2/report.json. Needs Docker and, for the relay check, Ollama on
# the host loopback with the allow-listed model.
attack:
	uv run python -m attacks.driver

attack-quick:
	uv run python -m attacks.driver --quick

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
