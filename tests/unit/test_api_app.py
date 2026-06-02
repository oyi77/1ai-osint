from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.app import app


def test_health_endpoint():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_and_poll_scan_job():
    client = TestClient(app)
    with patch("src.api.app._run_job", new_callable=AsyncMock):
        created = client.post("/v1/scan", json={"target": "fixture", "profile": "fast"})
    assert created.status_code == 200
    job_id = created.json()["job_id"]
    status = client.get(f"/v1/scan/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] in ("queued", "running", "completed")


def test_get_scan_404():
    client = TestClient(app)
    assert client.get("/v1/scan/missing").status_code == 404


@pytest.mark.asyncio
async def test_run_job_completes():
    from unittest.mock import MagicMock

    from src.api.app import ScanRequest, _JOBS, _run_job

    job_id = "job-unit-test"
    _JOBS[job_id] = {"status": "queued"}
    req = ScanRequest(target="fixture", profile="fast", case_id="")

    fake_result = MagicMock()
    fake_intel = MagicMock()
    with patch("src.modules.deep_scan.engine.DeepScanEngine") as eng_cls:
        eng_cls.return_value.scan = AsyncMock(return_value=fake_result)
        with patch("src.modules.deep_scan.report_generator.generate_intel_report", return_value=fake_intel):
            with patch("src.modules.deep_scan.exports.export_report", side_effect=lambda _r, fmt: b"pdf" if fmt == "pdf" else "{}"):
                await _run_job(job_id, req)
    assert _JOBS[job_id]["status"] == "completed"
    assert "intel" in _JOBS[job_id]


@pytest.mark.asyncio
async def test_run_job_failure():
    from src.api.app import ScanRequest, _JOBS, _run_job

    job_id = "job-fail"
    _JOBS[job_id] = {"status": "queued"}
    req = ScanRequest(target="x", profile="fast")
    with patch("src.modules.deep_scan.engine.DeepScanEngine", side_effect=RuntimeError("boom")):
        await _run_job(job_id, req)
    assert _JOBS[job_id]["status"] == "failed"
    assert "error" in _JOBS[job_id]
