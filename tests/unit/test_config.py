"""Tests for configuration module."""

from src.core.config import Settings


class TestSettings:
    def test_default_values(self):
        s = Settings()
        assert s.log_level == "INFO"
        assert s.cache_dir == ".osint_cache"
        assert s.omniroute_base_url == "http://localhost:3000/v1"

    def test_platform_defaults(self):
        s = Settings()
        assert s.scanner_workers == 20
        assert s.scanner_mode == "targeted"
        assert s.db_type == "sqlite"
        assert s.rate_limit_file == ".osint_rate_limit.json"
        assert s.audit_log_path == ".osint_audit.jsonl"
        assert s.api_cors_origins == ""
        assert s.api_jobs_dir == ""

    def test_effective_openai_base_url_omniroute(self):
        s = Settings(omniroute_api_key="test-key", omniroute_base_url="http://custom:4000/v1")
        assert s.effective_openai_base_url == "http://custom:4000/v1"

    def test_effective_openai_base_url_direct(self):
        s = Settings(omniroute_api_key="", openai_base_url="https://api.openai.com/v1")
        assert s.effective_openai_base_url == "https://api.openai.com/v1"

    def test_effective_api_key_omniroute(self):
        s = Settings(omniroute_api_key="omni-key", openai_api_key="openai-key")
        assert s.effective_openai_api_key == "omni-key"

    def test_effective_api_key_direct(self):
        s = Settings(omniroute_api_key="", openai_api_key="openai-key")
        assert s.effective_openai_api_key == "openai-key"
