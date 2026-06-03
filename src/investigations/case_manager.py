"""Investigation case folders — persistent case storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.config import Settings


class CaseManager:
    """Manage investigations/<case_id>/ with runs, reports, and metadata."""

    def __init__(self, base_dir: Path | None = None):
        root = base_dir or Settings().project_root / "investigations"
        self.base_dir = Path(root)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def case_path(self, case_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in case_id)
        return self.base_dir / safe

    def ensure_case(self, case_id: str, target: str) -> Path:
        path = self.case_path(case_id)
        path.mkdir(parents=True, exist_ok=True)
        (path / "runs").mkdir(exist_ok=True)
        meta_file = path / "case.json"
        if not meta_file.exists():
            meta_file.write_text(
                json.dumps(
                    {
                        "case_id": case_id,
                        "primary_target": target,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        return path

    def save_run(
        self,
        case_id: str,
        target: str,
        deep_result: Any,
        intel_report: Any,
        *,
        html: str = "",
        json_report: str = "",
        stix: str = "",
        pdf_bytes: bytes | None = None,
    ) -> Path:
        """Persist one deep-scan run under the case."""
        case_dir = self.ensure_case(case_id, target)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = case_dir / "runs" / ts
        run_dir.mkdir(parents=True, exist_ok=True)

        if hasattr(deep_result, "to_dict"):
            (run_dir / "deep_scan.json").write_text(
                json.dumps(deep_result.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
        if json_report:
            (run_dir / "intel.json").write_text(json_report, encoding="utf-8")
        if html:
            (run_dir / "briefing.html").write_text(html, encoding="utf-8")
        if stix:
            (run_dir / "intel.stix.json").write_text(stix, encoding="utf-8")
        if pdf_bytes:
            (run_dir / "briefing.pdf").write_bytes(pdf_bytes)

        (case_dir / "latest").write_text(str(run_dir.name), encoding="utf-8")
        return run_dir

    def load_previous_intel(self, case_id: str) -> dict | None:
        """Load latest intel JSON for delta comparison."""
        case_dir = self.case_path(case_id)
        latest = case_dir / "latest"
        if not latest.exists():
            return None
        run_name = latest.read_text(encoding="utf-8").strip()
        intel_path = case_dir / "runs" / run_name / "intel.json"
        if not intel_path.exists():
            return None
        return json.loads(intel_path.read_text(encoding="utf-8"))
