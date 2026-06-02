"""Environment health checks for 1ai-osint."""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass

from src.config import Settings
from src.modules.deep_scan.breach_router import breach_status_report


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


def run_doctor() -> list[CheckResult]:
    """Run all environment checks."""
    results: list[CheckResult] = []
    py = sys.version_info
    results.append(CheckResult(
        "python",
        py >= (3, 10),
        f"{py.major}.{py.minor}.{py.micro}",
    ))

    for binary, label in (
        ("sherlock", "sherlock-project (required)"),
        ("maigret", "maigret (optional)"),
        ("phoneinfoga", "phoneinfoga (optional)"),
    ):
        path = shutil.which(binary)
        required = binary == "sherlock"
        results.append(CheckResult(
            label,
            bool(path) if required else True,
            path or ("not found" + (" — pip install sherlock-project" if required else "")),
        ))

    settings = Settings()
    for module, ok, env_name in breach_status_report(settings):
        # Breach keys optional — reported but do not fail doctor exit code
        results.append(CheckResult(
            f"breach:{module}",
            True,
            f"{env_name}={'set' if ok else 'missing (optional)'}",
        ))

    try:
        from src.modules.people_finder.search import PeopleFinderSearch

        providers = PeopleFinderSearch()._get_providers()
        results.append(CheckResult(
            "people_finder providers",
            "sherlock" in providers,
            ", ".join(providers.keys()) or "none",
        ))
    except Exception as exc:
        results.append(CheckResult("people_finder providers", False, str(exc)))

    return results


def format_doctor_report(results: list[CheckResult]) -> str:
    lines = ["1ai-osint doctor", "=" * 40]
    failed = 0
    for r in results:
        mark = "OK" if r.ok else "FAIL"
        if not r.ok:
            failed += 1
        lines.append(f"[{mark}] {r.name}: {r.detail}")
    lines.append("=" * 40)
    lines.append(f"{len(results) - failed}/{len(results)} checks passed")
    if failed:
        lines.append("Fix FAIL items before running deep scans.")
    else:
        unset = [r.name for r in results if "missing" in r.detail]
        if unset:
            lines.append("Tip: set breach API keys in .env for agency-grade §IV intel.")
    return "\n".join(lines)
