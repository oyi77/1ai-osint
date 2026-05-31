# Autopilot Spec: Complete 1ai-osint ZKIT Codebase

## Goal
Complete all stub implementations, add missing test coverage, fix config inconsistencies, and bring the codebase to a fully functional, well-tested state.

## Scope

### 1. Stub Implementations (4 files)
- `src/vendor/chiasmodon/leak_dehashed/__init__.py` — implement DeHashedTool with real API calls
- `src/vendor/chiasmodon/leak_aggregator/__init__.py` — implement LeakAggregatorTool combining all sources
- `src/vendor/chiasmodon/leak_pastebin/__init__.py` — implement PastebinTool with scraping
- `src/vendor/chiasmodon/leak_reddit/__init__.py` — implement RedditLeakTool with Reddit search
- `src/vendor/chiasmodon/__init__.py` — add proper exports
- `src/vendor/chiasmodon/chiasmodon/__init__.py` — implement OSINTAggregatorTool

### 2. Test Coverage (highest priority gaps)
- 8 leak_finder/sources/ adapters — unit tests with mocked HTTP
- 21 chiasmodon providers — unit tests with mocked HTTP/subprocess
- 6 output module files (json_formatter, pdf_export, pdf_generator, sarif_formatter, sarif, report_generator partial)
- AI prompts (entity_extraction, false_positive_filter)
- AI schemas (responses.py)
- base.py module class
- hit_logger.py, _leak_shared.py, leak_scanner_telegram.py

### 3. Config Fixes
- Align coverage gates: pyproject.toml and CI both to 80%
- Add missing env vars to .env.example: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, WEBHOOK_URL

### 4. Out of Scope
- Empty output subdirs (pdf/, sarif/, json/) — these are documentation placeholders, real code is in parent dir
- `learn()` no-ops — by design (future work)
- New features or modules

## Success Criteria
- All stubs replaced with real implementations
- All new implementations have tests
- `pytest` passes with 80%+ coverage
- `ruff check` clean
