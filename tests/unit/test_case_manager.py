import json
from pathlib import Path

from src.investigations.case_manager import CaseManager


def test_case_save_and_load(tmp_path: Path):
    cm = CaseManager(base_dir=tmp_path)
    cm.save_run("case-1", "Alice", {"x": 1}, {"target": "Alice"}, html="<html/>", json_report='{"target":"Alice"}')
    prev = cm.load_previous_intel("case-1")
    assert prev["target"] == "Alice"
    assert (tmp_path / "case-1" / "runs").is_dir()


def test_save_run_with_to_dict_and_stix(tmp_path: Path):
    class DeepResult:
        def to_dict(self):
            return {"target": "Bob"}

    cm = CaseManager(base_dir=tmp_path)
    run = cm.save_run(
        "case-2",
        "Bob",
        DeepResult(),
        {"target": "Bob"},
        stix="{}",
        pdf_bytes=b"%PDF-1.4",
    )
    assert (run / "deep_scan.json").exists()
    assert (run / "briefing.pdf").exists()
    assert cm.load_previous_intel("case-2") is None
