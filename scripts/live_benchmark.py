#!/usr/bin/env python3
"""Live side-by-side benchmark: 1ai-osint vs popular OSINT tools.

Runs the same target through 1ai-osint and whatever external OSINT tools are
installed on this machine, then emits a standardized scorecard so the tools
can be compared on equal footing.

Tools covered:

- ``1ai-osint``  — our own engine (``scan <target> --module all --output json``)
- ``sherlock``   — username enumeration (needs a username target)
- ``maigret``    — username enumeration (needs a username target)
- ``theHarvester`` — email/host/subdomain harvesting (needs a domain target)
- ``holehe``     — email-to-service account check (needs an email target)
- ``spiderfoot`` — OSINT automation; CLI runs an ephemeral scan via ``-s``
- ``maltego``    — commercial GUI; headless invocation is not supported
- ``recon-ng``   — interactive console; not runnable headless without a
  workspace script (pass ``--recon-script`` to enable)

Two modes:

- ``detect`` (default) — reports which tools are installed/usable without
  touching the network. Safe to run anywhere.
- ``live`` — actually executes each available tool against ``--target``.
  External calls are wall-clock capped by ``--tool-timeout`` and killed on
  timeout. Use with an API-keyed environment for meaningful comparison.

Like ``benchmark.py``/``soak.py``, ``--json`` emits a single JSON receipt on
stdout while the human report goes to stderr, so ``> file`` yields a
machine-readable artifact CI can archive.

Usage:
    python scripts/live_benchmark.py --target testuser
    python scripts/live_benchmark.py --target johndoe@example.com --mode live --json > receipt.json 2> report.txt
    python scripts/live_benchmark.py --target example.com --mode live --tool theharvester --scorecard /tmp/sc.md
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.models import Severity  # noqa: E402

RECEIPT_SCHEMA = "1ai-osint.live-benchmark.receipt.v1"

# Tool name -> binary it is detected by. ``None`` means headless invocation is
# not supported (GUI / interactive console).
TOOL_BINARIES = {
    "sherlock": "sherlock",
    "maigret": "maigret",
    "theharvester": "theHarvester",
    "holehe": "holehe",
    "spiderfoot": "spiderfoot",
    "maltego": None,
    "recon-ng": "recon-ng",
}
DEFAULT_TOOLS = ("1ai-osint", "sherlock", "maigret", "theharvester", "holehe", "spiderfoot", "maltego", "recon-ng")


def _git_commit() -> str:
    """Return the current HEAD commit hash, or ``unknown`` when unavailable."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _uv_version() -> str:
    """Return the installed uv version string, or ``unknown``."""
    uv = shutil.which("uv")
    if not uv:
        return "unknown"
    try:
        out = subprocess.check_output([uv, "--version"], text=True, stderr=subprocess.DEVNULL)
        return out.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _machine_spec() -> dict:
    """Capture a best-effort machine description for receipt provenance."""
    model = "unknown"
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "machine": platform.machine(),
        "cpu_count": os.cpu_count() or 0,
        "cpu_model": model,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "uv": _uv_version(),
    }


def _resolve_1ai_osint_cmd() -> list[str] | None:
    """Resolve the command that runs our own CLI. Prefers installed console
    script, then the local venv, then ``uv run``."""
    exe = shutil.which("1ai-osint")
    if exe:
        return [exe]
    venv_bin = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "1ai-osint"
    if venv_bin.exists():
        return [str(venv_bin)]
    if shutil.which("uv"):
        return ["uv", "run", "--no-sync", "1ai-osint"]
    return None


def _detect_status(tool: str) -> dict:
    """Return availability metadata for a tool without executing it."""
    binary = TOOL_BINARIES.get(tool)
    if binary is None:
        return {"status": "not-applicable", "binary": None, "note": "headless invocation not supported"}
    path = shutil.which(binary)
    if not path:
        return {"status": "missing", "binary": None, "note": f"binary '{binary}' not on PATH"}
    return {"status": "installed", "binary": path, "note": None}


def _run_cmd(cmd: list[str], timeout: int, report) -> tuple[int, str, str, float]:
    """Run a command, cap wall time, return (exit_code, stdout, stderr, wall_sec)."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        return proc.returncode, proc.stdout, proc.stderr, time.perf_counter() - t0
    except subprocess.TimeoutExpired as exc:
        report(f"    ! timed out after {timeout}s: {' '.join(cmd[:3])} ...")
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, out, err, time.perf_counter() - t0
    except OSError as exc:
        report(f"    ! failed to launch: {exc}")
        return -2, "", str(exc), time.perf_counter() - t0


def _parse_1ai_osint(stdout: str) -> tuple[int, int, str | None]:
    """Parse our scan's JSON array output into (findings, critical, note).

    ``scan --output json`` emits a list of ``ScanResult.model_dump()``
    objects. ``finding_count``/``critical_count`` are model *properties*, so
    they never appear in the dump — count them from the nested ``findings``
    list and the per-result ``module`` field instead.
    """
    text = stdout.strip()
    if not text:
        return 0, 0, "no stdout"
    try:
        data = json.loads(text)
        if not isinstance(data, list):
            return 0, 0, "unexpected JSON shape (expected list)"
        findings = 0
        critical = 0
        names: list[str] = []
        for r in data:
            if not isinstance(r, dict):
                continue
            names.append(str(r.get("module")))
            fs = r.get("findings") or []
            findings += len(fs)
            critical += sum(1 for f in fs if isinstance(f, dict) and f.get("severity") == Severity.CRITICAL)
        return findings, critical, f"modules: {', '.join(names)}"
    except (ValueError, TypeError):
        # Fall back to grepping the human output for counts.
        m = re.findall(r"(\d+) findings?", text)
        return (int(m[-1]) if m else 0), 0, "JSON parse failed; heuristic count"


def _parse_generic_counts(tool: str, stdout: str) -> tuple[int, str | None]:
    """Best-effort finding count per tool. Returns (count, note)."""
    if tool == "sherlock":
        hit_lines = [ln for ln in stdout.splitlines() if ln.startswith("[+]")]
        return len(hit_lines), f"{len(hit_lines)} '[+]' hit lines"
    if tool == "maigret":
        m = re.search(r"Total found:\s*(\d+)", stdout, re.IGNORECASE)
        if m:
            return int(m.group(1)), None
        hits = len(re.findall(r"\[\+\]", stdout))
        return hits, "no 'Total found' line; counted '[+]' markers"
    if tool == "theharvester":
        total = 0
        for kind in ("Emails", "Hosts", "Links", "Virtual Hosts"):
            m = re.search(rf"{kind}\s+found:\s*(\d+)", stdout, re.IGNORECASE)
            if m:
                total += int(m.group(1))
        return total, None if total else "no '<kind> found:' lines parsed"
    if tool == "holehe":
        used = len(re.findall(r"\[\+\]\s+.*\bused\b", stdout, re.IGNORECASE))
        return used, f"{used} accounts marked 'used'"
    if tool == "spiderfoot":
        hits = len(re.findall(r"\[\+\]\s+", stdout))
        return hits, "spiderfoot -q; counted event lines"
    return 0, f"no parser for {tool}; count reported as 0"


def _tool_args(tool: str, target: str, recon_script: str | None) -> list[str] | None:
    """Build argv for an external tool; None when the tool can't run headless."""
    if tool == "sherlock":
        return [shutil.which("sherlock") or "sherlock", target]
    if tool == "maigret":
        return [shutil.which("maigret") or "maigret", target]
    if tool == "theharvester":
        return [shutil.which("theHarvester") or "theHarvester", "-d", target, "-b", "all"]
    if tool == "holehe":
        return [shutil.which("holehe") or "holehe", target]
    if tool == "spiderfoot":
        return [shutil.which("spiderfoot") or "spiderfoot", "-s", target, "-m", "all", "-q"]
    if tool == "recon-ng":
        return [shutil.which("recon-ng") or "recon-ng", "-r", recon_script] if recon_script else None
    return None  # maltego: GUI only


def _run_tool(tool: str, target: str, scan_timeout: int, tool_timeout: int, recon_script: str | None, report) -> dict:
    """Run one tool against the target; never raises."""
    if tool == "1ai-osint":
        cmd = _resolve_1ai_osint_cmd()
        if not cmd:
            return {"tool": tool, "status": "not-installed", "note": "no 1ai-osint entry point found"}
        cmd = cmd + ["scan", target, "--module", "all", "--output", "json", "--timeout", str(scan_timeout)]
        exit_code, out, err, wall = _run_cmd(cmd, tool_timeout, report)
        if exit_code != 0:
            return {
                "tool": tool,
                "status": "error",
                "exit_code": exit_code,
                "wall_sec": round(wall, 3),
                "findings": 0,
                "critical": 0,
                "note": f"scan exited {exit_code}: {err.strip()[:200]}",
            }
        findings, critical, note = _parse_1ai_osint(out)
        return {
            "tool": tool,
            "status": "ran",
            "exit_code": exit_code,
            "wall_sec": round(wall, 3),
            "findings": findings,
            "critical": critical,
            "note": note,
        }

    status = _detect_status(tool)
    if status["status"] != "installed":
        return {"tool": tool, "status": status["status"], "note": status["note"]}
    args = _tool_args(tool, target, recon_script)
    if args is None:
        return {"tool": tool, "status": "not-applicable", "note": "requires interactive/GUI session"}
    exit_code, out, err, wall = _run_cmd(args, tool_timeout, report)
    if exit_code == -1:
        return {
            "tool": tool,
            "status": "timeout",
            "wall_sec": round(wall, 3),
            "findings": 0,
            "critical": 0,
            "note": f"killed after {tool_timeout}s",
        }
    if exit_code not in (0, 1):
        return {
            "tool": tool,
            "status": "error",
            "exit_code": exit_code,
            "wall_sec": round(wall, 3),
            "findings": 0,
            "critical": 0,
            "note": err.strip()[:200] or f"exit {exit_code}",
        }
    findings, note = _parse_generic_counts(tool, out)
    return {
        "tool": tool,
        "status": "ran",
        "exit_code": exit_code,
        "wall_sec": round(wall, 3),
        "findings": findings,
        "critical": 0,
        "note": note,
    }


def _write_scorecard(path: str, target: str, results: list[dict], mode: str, report) -> None:
    """Write a markdown scorecard for humans."""
    lines = [
        f"# OSINT Tool Live Benchmark — `{target}`",
        "",
        f"- Mode: `{mode}`",
        f"- Commit: `{_git_commit()}`",
        f"- Timestamp: {datetime.now(timezone.utc).isoformat()}",
        f"- Machine: {platform.machine()} ({os.cpu_count() or '?'} cores)",
        "",
        "| Tool | Status | Findings | Critical | Wall (s) | Note |",
        "|------|--------|----------|----------|----------|------|",
    ]
    for r in results:
        lines.append(
            f"| {r['tool']} | {r['status']} | {r.get('findings', '-')} | {r.get('critical', '-')} "
            f"| {r.get('wall_sec', '-')} | {r.get('note') or ''} |"
        )
    lines.append("")
    lines.append(
        "> Findings counts are tool-dependent (parsed from each tool's own output format) and are "
        "**not** directly comparable across tools without reading the notes column. Use this scorecard "
        "for breadth comparison, not as a raw-finding race."
    )
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        report(f"  Scorecard written: {path}")
    except OSError as exc:
        report(f"  ! could not write scorecard: {exc}")


def run_benchmark(
    target: str,
    tools: list[str],
    mode: str,
    scan_timeout: int,
    tool_timeout: int,
    recon_script: str | None,
    scorecard: str | None,
    as_json: bool = False,
) -> None:
    """Run the benchmark and emit the report + receipt."""
    out = sys.stderr if as_json else sys.stdout

    def _report(*a: Any, **kw: Any) -> None:
        print(*a, **kw, file=out)

    _report("=" * 62)
    _report("  Live OSINT Tool Benchmark")
    _report("=" * 62)
    _report(f"  Target:  {target}")
    _report(f"  Mode:    {mode}")
    _report(f"  Tools:   {', '.join(tools)}")
    _report("=" * 62)

    start = time.monotonic()
    results: list[dict] = []
    for tool in tools:
        _report(f"  [{tool}] {'detecting...' if mode == 'detect' else 'running...'}")
        if mode == "detect":
            if tool == "1ai-osint":
                cmd = _resolve_1ai_osint_cmd()
                results.append(
                    {
                        "tool": tool,
                        "status": "installed" if cmd else "missing",
                        "binary": cmd[0] if cmd else None,
                        "note": None if cmd else "no 1ai-osint entry point found",
                    }
                )
            else:
                results.append({"tool": tool, **_detect_status(tool)})
        else:
            results.append(_run_tool(tool, target, scan_timeout, tool_timeout, recon_script, _report))

    elapsed = time.monotonic() - start

    _report("")
    _report("=" * 62)
    _report("  RESULTS")
    _report("=" * 62)
    for r in results:
        if mode == "detect":
            _report(f"  {r['tool']:<14} {r['status']:<14} {r.get('binary') or r.get('note') or ''}")
        else:
            _report(
                f"  {r['tool']:<14} {r['status']:<12} "
                f"findings={r.get('findings', 0):<5} critical={r.get('critical', 0):<3} "
                f"wall={r.get('wall_sec', 0):.1f}s  {r.get('note') or ''}"
            )
    _report(f"  Elapsed: {elapsed:.1f}s")
    _report("=" * 62)

    if scorecard:
        _write_scorecard(scorecard, target, results, mode, _report)

    if mode == "detect":
        verdict = "DETECT"
        ran_any = False
    else:
        ran = [r for r in results if r["status"] == "ran"]
        ran_any = bool(ran)
        ours = [r for r in ran if r["tool"] == "1ai-osint"]
        externals = [r for r in ran if r["tool"] != "1ai-osint"]
        verdict = "COMPARED" if ours and externals else "INCOMPLETE"
    _report(f"  Verdict: {verdict}" + ("" if ran_any else " (install tools and re-run --mode live)"))
    _report("=" * 62)

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "tool": "scripts/live_benchmark.py",
        "commit": _git_commit(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "machine": _machine_spec(),
        "params": {
            "target": target,
            "mode": mode,
            "tools": tools,
            "scan_timeout_sec": scan_timeout,
            "tool_timeout_sec": tool_timeout,
        },
        "metrics": {"elapsed_sec": round(elapsed, 3), "tools": results},
        "verdict": verdict,
    }
    try:
        from src.core.source_registry import no_api_metrics

        receipt["transports"] = no_api_metrics()
    except Exception:
        receipt["transports"] = {}
    if as_json:
        print(json.dumps(receipt, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Live OSINT tool benchmark")
    parser.add_argument("--target", required=True, help="Username, email, or domain to benchmark against")
    parser.add_argument("--tool", default="all", help="Tool to run (default: all)")
    parser.add_argument(
        "--mode",
        choices=["detect", "live"],
        default="detect",
        help="detect = report installed tools only; live = actually run them",
    )
    parser.add_argument("--scan-timeout", type=int, default=60, help="Timeout per module for 1ai-osint scan")
    parser.add_argument("--tool-timeout", type=int, default=120, help="Wall-clock cap per external tool")
    parser.add_argument("--recon-script", default=None, help="Path to a recon-ng .rc script to enable recon-ng")
    parser.add_argument("--scorecard", default=None, help="Write a markdown scorecard to this path")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable JSON receipt on stdout")
    args = parser.parse_args()

    tools = list(DEFAULT_TOOLS) if args.tool == "all" else [args.tool]
    run_benchmark(
        target=args.target,
        tools=tools,
        mode=args.mode,
        scan_timeout=args.scan_timeout,
        tool_timeout=args.tool_timeout,
        recon_script=args.recon_script,
        scorecard=args.scorecard,
        as_json=args.json,
    )


if __name__ == "__main__":
    main()
