"""Tests for API job persistence + resume across process restarts.

The api app persists its in-memory job store to disk so jobs survive a
restart. Under pytest those save/load paths are normally no-ops; these tests
reload the module with AI_OSINT_JOBS_DIR pointed at a tmp dir and disable the
no-op so the real persistence code is exercised.
"""

import importlib

import pytest

import src.api.app as api_app


@pytest.fixture
def reloaded_app(monkeypatch, tmp_path):
    """Point the jobs store at tmp_path and reload the module so ``_JOBS_FILE``
    is recomputed; then disable the in-pytest save/load no-op."""
    monkeypatch.setenv("AI_OSINT_JOBS_DIR", str(tmp_path))
    module = importlib.reload(api_app)
    monkeypatch.setattr(module, "_in_pytest", lambda: False)
    return module


class TestJobPersistence:
    def test_save_then_load_round_trip(self, reloaded_app, tmp_path):
        job = {
            "job_id": "job-1",
            "target": "example.com",
            "status": "complete",
            "created_at": "2026-08-01T00:00:00",
        }
        reloaded_app._JOBS["job-1"] = job
        reloaded_app._save_jobs()
        assert (tmp_path / "jobs.json").exists()

        reloaded_app._JOBS.clear()
        restored = reloaded_app._load_jobs()
        assert restored["job-1"]["status"] == "complete"
        assert restored["job-1"]["target"] == "example.com"

    def test_running_job_restored_as_interrupted(self, reloaded_app, tmp_path):
        # A job persisted while mid-run must never resurrect as "running" —
        # a resumed runner would double-execute the scan.
        reloaded_app._JOBS["job-2"] = {
            "job_id": "job-2",
            "target": "victim.org",
            "status": "running",
            "created_at": "2026-08-01T00:00:00",
        }
        reloaded_app._save_jobs()

        reloaded_app._JOBS.clear()
        restored = reloaded_app._load_jobs()
        assert restored["job-2"]["status"] == "interrupted"

    def test_corrupt_file_returns_empty(self, reloaded_app, tmp_path):
        (tmp_path / "jobs.json").write_text("{not json", encoding="utf-8")
        reloaded_app._JOBS.clear()
        reloaded_app._load_jobs()  # must not raise
        assert reloaded_app._JOBS == {}

    def test_save_never_raises_on_write_failure(self, reloaded_app, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(reloaded_app.os, "replace", boom)
        reloaded_app._JOBS["job-3"] = {
            "job_id": "job-3",
            "status": "queued",
            "created_at": "2026-08-01T00:00:00",
        }
        reloaded_app._save_jobs()  # must not raise
