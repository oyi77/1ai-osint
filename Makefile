# Makefile for 1ai-osint

UV = uv
PYTHON = $(UV) run python
PYTEST = $(UV) run pytest
RUFF = $(UV) run ruff
MYPY = $(UV) run mypy

.PHONY: install test lint typecheck coverage ci clean run

install:
	$(UV) sync --group dev
	$(UV) run pre-commit install

test:
	rm -f .coverage
	$(PYTEST) -q --tb=short

coverage:
	rm -f .coverage
	$(PYTEST) -q --tb=short --cov=src --cov-report=term-missing

lint:
	$(RUFF) check src/ tests/

typecheck:
	$(MYPY) src/

ci: lint typecheck test
	@echo "CI pipeline passed"

run:
	$(UV) run uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +
