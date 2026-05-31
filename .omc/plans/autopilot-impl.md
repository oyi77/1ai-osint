# Autopilot Plan: Complete 1ai-osint

## Phase 2 — Execution (8 tasks)

### Task 1: Fix config inconsistencies
- Edit `pyproject.toml`: change `--cov-fail-under=79` to `80`
- Edit `.env.example`: add TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WEBHOOK_URL

### Task 2: Implement DeHashed stub
- Edit `src/vendor/chiasmodon/leak_dehashed/__init__.py`
- Use requests to call DeHashed API (dehashed.com/api/v1/search)
- Add `test_dehashed.py` with mocked HTTP

### Task 3: Implement Pastebin stub
- Edit `src/vendor/chiasmodon/leak_pastebin/__init__.py`
- Use httpx to scrape Pastebin search results
- Add `test_pastebin.py` with mocked HTTP

### Task 4: Implement Reddit stub
- Edit `src/vendor/chiasmodon/leak_reddit/__init__.py`
- Use httpx to search Reddit via old.reddit.com search
- Add `test_reddit.py` with mocked HTTP

### Task 5: Implement LeakAggregator stub
- Edit `src/vendor/chiasmodon/leak_aggregator/__init__.py`
- Combine all leak sources via asyncio.gather()
- Add `test_aggregator.py` with mocked sources

### Task 6: Fix chiasmodon __init__ exports
- Edit `src/vendor/chiasmodon/__init__.py` — add proper imports/exports
- Edit `src/vendor/chiasmodon/chiasmodon/__init__.py` — implement OSINTAggregatorTool

### Task 7: Add tests for leak_finder sources
- Create `tests/unit/test_leak_sources.py`
- Test all 8 source adapters with mocked HTTP responses
- Cover: successful search, empty results, API errors, timeout

### Task 8: Add tests for remaining untested modules
- `tests/unit/test_chiasmodon_providers.py` — test all 19 providers
- `tests/unit/test_output_formatters.py` — test json/pdf/sarif formatters
- `tests/unit/test_ai_prompts.py` — test prompt templates
- `tests/unit/test_base_module.py` — test base class
- `tests/unit/test_hit_logger.py` — test hit logging

## Phase 3 — QA
- Run pytest, fix failures, iterate up to 5 cycles

## Phase 4 — Validation
- Architect: functional completeness
- Security-reviewer: no secrets in code, safe API handling
- Code-reviewer: quality and consistency
