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
        with patch(
            "src.modules.deep_scan.report_generator.generate_intel_report_with_ai",
            return_value=fake_intel,
        ):
            with patch(
                "src.modules.deep_scan.exports.export_report",
                side_effect=lambda _r, fmt: b"pdf" if fmt == "pdf" else "{}",
            ):
                await _run_job(job_id, req)
    assert _JOBS[job_id]["status"] == "completed"
    assert "intel" in _JOBS[job_id]


@pytest.mark.asyncio
async def test_run_job_failure():
    from src.api.app import ScanRequest, _JOBS, _run_job

    job_id = "job-fail"
    _JOBS[job_id] = {"status": "queued"}
    req = ScanRequest(target="x", profile="fast")
    with patch(
        "src.modules.deep_scan.engine.DeepScanEngine", side_effect=RuntimeError("boom")
    ):
        await _run_job(job_id, req)
    assert _JOBS[job_id]["status"] == "failed"
    assert "error" in _JOBS[job_id]


def test_list_jobs():
    from src.api.app import _JOBS

    client = TestClient(app)
    _JOBS["job-test-1"] = {
        "status": "queued",
        "target": "target1",
        "profile": "fast",
        "budget": 10.0,
        "created_at": "2026-06-02T22:22:22",
    }
    resp = client.get("/v1/jobs")
    assert resp.status_code == 200
    assert any(j["job_id"] == "job-test-1" for j in resp.json())


def test_ui_endpoints():
    client = TestClient(app)
    resp = client.get("/ui")
    assert resp.status_code == 200
    assert "1ai-osint Control Center" in resp.text

    resp2 = client.get("/")
    assert resp2.status_code == 200
    assert "1ai-osint Control Center" in resp2.text


@pytest.mark.asyncio
async def test_run_job_with_case_id():
    from unittest.mock import MagicMock
    from src.api.app import ScanRequest, _JOBS, _run_job

    job_id = "job-unit-test-case-id"
    _JOBS[job_id] = {"status": "queued"}
    req = ScanRequest(target="fixture", profile="fast", case_id="unit-case-id")

    fake_result = MagicMock()
    fake_intel = MagicMock()

    with patch("src.modules.deep_scan.engine.DeepScanEngine") as eng_cls:
        eng_cls.return_value.scan = AsyncMock(return_value=fake_result)
        with patch(
            "src.modules.deep_scan.report_generator.generate_intel_report_with_ai",
            return_value=fake_intel,
        ):
            with patch(
                "src.modules.deep_scan.exports.export_report",
                side_effect=lambda _r, fmt: b"pdf" if fmt == "pdf" else "{}",
            ):
                with patch(
                    "src.investigations.case_manager.CaseManager"
                ) as mock_case_mgr:
                    await _run_job(job_id, req)
                    assert mock_case_mgr.return_value.save_run.called
    assert _JOBS[job_id]["status"] == "completed"


@pytest.mark.asyncio
async def test_run_job_returns_valid_identity_graph():
    from unittest.mock import MagicMock
    import json
    from src.api.app import ScanRequest, _JOBS, _run_job
    from src.modules.deep_scan.models_report import (
        IntelReport,
        IdentityGraph as ReportIdentityGraph,
    )
    from src.modules.deep_scan.models_report import (
        IdentityNode as ReportIdentityNode,
        IdentityEdge as ReportIdentityEdge,
    )

    job_id = "job-unit-test-graph"
    _JOBS[job_id] = {"status": "queued"}
    req = ScanRequest(target="test_target", profile="fast", case_id="")

    fake_result = MagicMock()
    # Construct a real IntelReport with a valid identity graph
    intel_report = IntelReport(
        report_id="test-rep",
        target="test_target",
        identity_graph=ReportIdentityGraph(
            nodes=[
                ReportIdentityNode(
                    id="node1", label="test_target", type="name", weight=1.0
                ),
                ReportIdentityNode(
                    id="node2", label="test@email.com", type="email", weight=0.8
                ),
            ],
            edges=[
                ReportIdentityEdge(
                    source_id="node1",
                    target_id="node2",
                    relationship="linked",
                    weight=0.9,
                    evidence_ids=[],
                ),
            ],
        ),
    )

    with patch("src.modules.deep_scan.engine.DeepScanEngine") as eng_cls:
        eng_cls.return_value.scan = AsyncMock(return_value=fake_result)
        with patch(
            "src.modules.deep_scan.report_generator.generate_intel_report_with_ai",
            return_value=intel_report,
        ):
            with patch("src.investigations.case_manager.CaseManager"):
                await _run_job(job_id, req)

    assert _JOBS[job_id]["status"] == "completed"
    assert "intel" in _JOBS[job_id]
    intel_data = json.loads(_JOBS[job_id]["intel"])
    assert "identity_graph" in intel_data
    graph = intel_data["identity_graph"]
    assert len(graph["nodes"]) == 2
    assert graph["nodes"][0]["id"] == "node1"
    assert graph["nodes"][0]["label"] == "test_target"
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["source_id"] == "node1"
    assert graph["edges"][0]["target_id"] == "node2"
