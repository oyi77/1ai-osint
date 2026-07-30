"""Shared test fixtures for 1ai-osint."""

from pathlib import Path
from typing import AsyncGenerator

import pytest

from src.core.cache import Cache
from src.core.config import Settings
from src.core.database import Database, SQLiteBackend
from src.core.models import BreachRecord, Finding, Identity, ScanResult, Severity
from src.core.rate_limiter import RateLimiter


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test isolation."""
    return tmp_path


@pytest.fixture
def test_settings(tmp_dir: Path) -> Settings:
    """Provide test-specific settings with isolated paths."""
    return Settings(
        cache_dir=str(tmp_dir / "cache"),
        rate_limit_file=str(tmp_dir / "rate_limit.json"),
        zkit_salt="test-salt-for-unit-tests",
        log_level="DEBUG",
    )


@pytest.fixture
async def test_db(tmp_dir: Path) -> AsyncGenerator[Database, None]:
    """Provide an in-memory-like SQLite database for testing."""
    db = Database(backend=SQLiteBackend(db_path=tmp_dir / "test.db"))
    await db.init_schema()
    yield db
    await db.close()


@pytest.fixture
def test_cache(tmp_dir: Path) -> Cache:
    """Provide an isolated cache instance."""
    return Cache(cache_dir=tmp_dir / "cache", default_ttl=60)


@pytest.fixture
def test_rate_limiter(tmp_dir: Path) -> RateLimiter:
    """Provide an isolated rate limiter."""
    return RateLimiter(
        state_file=tmp_dir / "rate_limit.json",
        requests_per_minute=120,
        burst=20,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Provide a sample Finding for testing."""
    return Finding(
        id="test-finding-001",
        module="test_module",
        title="Test finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        raw_data={"email": "test@example.com", "source": "test"},
        confidence=0.8,
        tags=["test", "sample"],
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Provide a sample ScanResult for testing."""
    return ScanResult(
        scan_id="test-scan-001",
        module="test_module",
        target="test@example.com",
        status="ok",
        findings=[sample_finding],
        metadata={"test": True},
    )


@pytest.fixture
def sample_breach_record() -> BreachRecord:
    """Provide a sample BreachRecord for testing."""
    return BreachRecord(
        source="test_breach",
        email="test@example.com",
        username="testuser",
        domain="example.com",
        breach_date=None,
        description="Test breach",
        data_classes=["email", "password"],
        severity=Severity.HIGH,
    )


@pytest.fixture
def sample_identity() -> Identity:
    """Provide a sample Identity for testing."""
    return Identity(
        zkit_hash="a]b1c2d3e4f5",
        attributes={"email": "test@example.com"},
        correlation_id="corr-001",
        sources=["test_module"],
        confidence=0.9,
    )


@pytest.fixture
def sample_secrets_path() -> Path:
    """Return path to sample secrets test fixture."""
    return Path(__file__).parent / "fixtures" / "sample_secrets.json"


@pytest.fixture
def sample_identities_path() -> Path:
    """Return path to test identities fixture."""
    return Path(__file__).parent / "fixtures" / "test_identities.json"
