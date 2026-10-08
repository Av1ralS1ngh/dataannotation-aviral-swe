.PHONY: install test lint up down smoke logs

install:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest

lint:
	python3 -m ruff check src tests

up:
	docker compose up --build -d

down:
	docker compose down

smoke:
	docker compose exec admission-a /workspace/scripts/smoke.sh

logs:
	docker compose logs -f admission-a admission-b publisher-a publisher-b
