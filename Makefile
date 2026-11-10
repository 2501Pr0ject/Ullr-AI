.PHONY: lint test secrets build up down attack attack-quick

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
