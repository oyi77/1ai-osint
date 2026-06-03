# Makefile for 1ai-osint

PYTHON = $(shell [ -d .venv ] && echo .venv/bin/python || echo python)
PIP = $(shell [ -d .venv ] && echo .venv/bin/pip || echo pip)
PYTEST = $(shell [ -d .venv ] && echo .venv/bin/pytest || echo pytest)
UVICORN = $(shell [ -d .venv ] && echo .venv/bin/uvicorn || echo uvicorn)

.PHONY: install test lint run clean

install:
	$(PIP) install -e ".[dev]"
	$(shell [ -d .venv ] && echo .venv/bin/pre-commit || echo pre-commit) install

test:
	rm -f .coverage
	$(PYTEST)

lint:
	$(PYTHON) -m ruff check src/ tests/
	$(PYTHON) -m ruff format --check src/ tests/

run:
	$(UVICORN) src.api.app:app --host 127.0.0.1 --port 8000 --reload

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +
