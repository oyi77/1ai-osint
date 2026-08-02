"""Per-source live baseline probe for keyless deep-scan sources.

Standalone verification script (NOT pytest — deliberately hits real public
endpoints, which the repo's test policy requires tests to mock).

What it does
------------
For every keyless module that the DeepScanEngine would actually run in 0-API
mode (``no_api=True``) and that maps to a discoverable ``*_source.py`` class:

1. Host reachability probe — GET the class ``BASE_URL``/``BASE`` with a short
   timeout. Any HTTP status (200/301/403/429/404...) proves the host answers;
   connection errors/timeouts prove it does not.
2. Functional probe — call ``search_for_address(identifier)`` with a synthetic
   identifier chosen from the module's ``MODULE_INPUTS`` types (falling back to
   ``fetch_raw_leaks()`` for feed-style sources). Never touches real PII.

Verdicts (honest, evidence-only — no retries, no claims beyond what a single
live call produced):

- ``verified-live``   — functional call returned >= 1 leak
- ``reachable-no-data`` — host answered, functional call returned 0 leaks
- ``failed``          — host unreachable or the call raised/timed out
- ``skipped``         — no usable synthetic identifier (NAME/NIK/SOCIAL only),
                        or the source is a TOOL/LOCAL CLI wrapper (its transport
                        is a local binary, not an endpoint)

Outputs (keyed by git commit so results are reproducible per revision):
- docs/evidence/live/source_probe_<git-short-hash>.json
- docs/evidence/live/source_probe_<git-short-hash>.md
- docs/evidence/live/history.json   (appended per sweep — one row per source)
- docs/evidence/live/uptime_report.md  (via ``--history`` mode)

``--history`` mode: no network calls. Reads the accumulated history.json and
renders the uptime report (per-source uptime %, failure-class breakdown
404/429/403/connection/parse/other, hit rates by category, degraded flags).

This script does not call ``run_source_scan``: the consent/RBAC/ToS gates and
the audit log live in the source adapter, and a verification sweep should not
simulate authorized-scan traffic nor pollute .osint_audit.jsonl.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.core.source_registry import kind_of  # noqa: E402
from src.modules.deep_scan import IdentifierType  # noqa: E402
from src.modules.deep_scan._module_config import MODULE_INPUTS  # noqa: E402
from src.modules.deep_scan.engine import DeepScanEngine  # noqa: E402
from src.modules.sources import discover_sources  # noqa: E402
from src.modules.sources.base import BaseLeakSource, RawLeak  # noqa: E402

HOST_TIMEOUT = 10.0
FUNC_TIMEOUT = 15.0
SLEEP_BETWEEN = 1.5

# Synthetic, non-PII identifiers (US fictional 555-0100 number for phone).
IDENTIFIER_VALUES: dict[IdentifierType, str] = {
    IdentifierType.DOMAIN: "example.com",
    IdentifierType.IP: "8.8.8.8",
    IdentifierType.USERNAME: "octocat",
    IdentifierType.EMAIL: "john.doe@example.com",
    IdentifierType.CRYPTO_ADDRESS: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # BTC genesis
    IdentifierType.HASH: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    IdentifierType.PHONE: "+14155550100",
    IdentifierType.URL: "https://example.com",
}

# Identifier types that map to real-people PII or have no safe synthetic value.
SKIP_TYPES = frozenset(
    {
        IdentifierType.NAME,
        IdentifierType.NIK,
        IdentifierType.SOCIAL_PROFILE,
        IdentifierType.PASSWORD,
    }
)

# Identifier priority order when a module accepts several types.
IDENTIFIER_PRIORITY = [
    IdentifierType.DOMAIN,
    IdentifierType.IP,
    IdentifierType.USERNAME,
    IdentifierType.EMAIL,
    IdentifierType.CRYPTO_ADDRESS,
    IdentifierType.HASH,
    IdentifierType.PHONE,
    IdentifierType.URL,
]

TOOL_KINDS = frozenset({"tool", "local"})

BASE_ATTRS = ("BASE_URL", "BASE")

HISTORY_PATH = REPO_ROOT / "docs" / "evidence" / "live" / "history.json"


def git_short_hash() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def pick_identifier(module: str) -> tuple[IdentifierType | None, str | None]:
    types = MODULE_INPUTS.get(module, set())
    if not types:
        return None, None
    for t in IDENTIFIER_PRIORITY:
        if t in types:
            return t, IDENTIFIER_VALUES[t]
    # Only skip-worthy types remain.
    if any(t in SKIP_TYPES for t in types):
        return None, None
    # Any leftover type we have no value for.
    for t in types:
        if t in IDENTIFIER_VALUES:
            return t, IDENTIFIER_VALUES[t]
    return None, None


def base_url_of(cls: type) -> str | None:
    for attr in BASE_ATTRS:
        val = getattr(cls, attr, None)
        if isinstance(val, str) and val.startswith(("http://", "https://")):
            return val
    return None


async def host_probe(base_url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=HOST_TIMEOUT) as client:
            started = time.monotonic()
            resp = await client.get(base_url, follow_redirects=False)
            elapsed = time.monotonic() - started
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "latency_ms": round(elapsed * 1000),
            "error": None,
        }
    except Exception as exc:  # timeout / connection error
        return {
            "reachable": False,
            "status_code": None,
            "latency_ms": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def override_status(inst: object) -> str:
    """Return 'search_for_address' | 'fetch_raw_leaks' | 'unknown'."""
    cls_search = getattr(type(inst), "search_for_address", None)
    base_search = getattr(BaseLeakSource, "search_for_address", None)
    if cls_search is not None and cls_search is not base_search:
        return "search_for_address"
    if callable(getattr(inst, "fetch_raw_leaks", None)):
        return "fetch_raw_leaks"
    return "unknown"


async def func_probe(inst: object, identifier: str | None) -> dict:
    method = override_status(inst)
    started = time.monotonic()
    try:
        if method == "search_for_address":
            leaks = await asyncio.wait_for(cast(Any, inst).search_for_address(identifier), FUNC_TIMEOUT)
        elif method == "fetch_raw_leaks":
            leaks = await asyncio.wait_for(cast(Any, inst).fetch_raw_leaks(), FUNC_TIMEOUT)
        else:
            return {
                "method": method,
                "latency_ms": round((time.monotonic() - started) * 1000),
                "leak_count": 0,
                "samples": [],
                "error": "no callable method",
            }
        leaks = list(leaks or [])
        samples = []
        for leak in leaks[:2]:
            text = leak.text if isinstance(leak, RawLeak) else str(leak)
            url = leak.source_url if isinstance(leak, RawLeak) else ""
            samples.append({"text": text[:_MAX_SAMPLE], "source_url": url})
        return {
            "method": method,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "leak_count": len(leaks),
            "samples": samples,
            "error": None,
        }
    except asyncio.TimeoutError:
        return {
            "method": method,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "leak_count": 0,
            "samples": [],
            "error": f"TimeoutError: exceeded {FUNC_TIMEOUT}s",
        }
    except Exception as exc:
        return {
            "method": method,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "leak_count": 0,
            "samples": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


_MAX_SAMPLE = 160


def classify(row: dict) -> str:
    if row["skipped_reason"]:
        return "skipped"
    if row["functional"]["leak_count"] > 0:
        return "verified-live"
    if row["host"]["reachable"]:
        return "reachable-no-data"
    return "failed"


async def probe_one(module: str, cls: type, kind: str) -> dict:
    id_type, identifier = pick_identifier(module)
    skipped_reason = None
    if kind in TOOL_KINDS:
        skipped_reason = "tool/local CLI wrapper — transport is a local binary, not an endpoint"
    elif id_type is None:
        skipped_reason = "no safe synthetic identifier (NAME/NIK/SOCIAL/PASSWORD-only module)"

    row: dict[str, Any] = {
        "module": module,
        "source_class": cls.__name__,
        "kind": kind,
        "identifier_type": id_type.value if id_type else None,
        "identifier": identifier,
        "skipped_reason": skipped_reason,
        "host": {"reachable": None, "status_code": None, "latency_ms": None, "error": None},
        "functional": {
            "method": None,
            "latency_ms": None,
            "leak_count": None,
            "samples": [],
            "error": None,
        },
    }

    if skipped_reason:
        return row

    base_url = base_url_of(cls)
    if base_url:
        row["host"] = await host_probe(base_url)

    try:
        inst = cls()
    except Exception as exc:
        row["functional"]["error"] = f"instantiation: {type(exc).__name__}: {exc}"
        row["functional"]["leak_count"] = 0
        return row

    row["functional"] = await func_probe(inst, identifier)
    return row


async def main() -> int:
    if "--history" in sys.argv:
        history = load_history()
        report = render_uptime_report(history)
        out_dir = REPO_ROOT / "docs" / "evidence" / "live"
        out_dir.mkdir(parents=True, exist_ok=True)
        md_path = out_dir / "uptime_report.md"
        md_path.write_text(report)
        print(report)
        print(f"\nWrote {md_path}")
        return 0

    engine = DeepScanEngine(no_api=True)
    active_modules = engine._get_active_modules()
    sources = discover_sources()
    to_probe = [(m, sources[m]) for m in active_modules if m in sources]

    results: list[dict] = []
    for i, (module, cls) in enumerate(to_probe, start=1):
        kind = kind_of(module) or "unknown"
        row = await probe_one(module, cls, kind)
        row["verdict"] = classify(row)
        results.append(row)
        print(
            f"[{i:>2}/{len(to_probe)}] {module:<22} kind={kind:<10} "
            f"id={row['identifier_type'] or '-':<12} verdict={row['verdict']:<18} "
            f"host={row['host']['status_code'] or '-'} "
            f"leaks={row['functional']['leak_count']} "
            f"{'err=' + row['functional']['error'][:80] if row['functional']['error'] else ''}"
        )
        sys.stdout.flush()
        if i < len(to_probe):
            await asyncio.sleep(SLEEP_BETWEEN)

    revision = git_short_hash()
    generated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": generated_at,
        "git_revision": revision,
        "note": (
            "Single-shot live probe, 1 request per source, no retries. "
            "reachable-no-data does NOT mean the source is broken — the synthetic "
            "identifier may legitimately not exist there. Host 403/429 = reachable "
            "but blocked (recorded as evidence)."
        ),
        "totals": {
            "probed": len(results),
            "verified_live": sum(r["verdict"] == "verified-live" for r in results),
            "reachable_no_data": sum(r["verdict"] == "reachable-no-data" for r in results),
            "failed": sum(r["verdict"] == "failed" for r in results),
            "skipped": sum(r["verdict"] == "skipped" for r in results),
        },
        "results": results,
    }

    out_dir = REPO_ROOT / "docs" / "evidence" / "live"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"source_probe_{revision}.json"
    json_path.write_text(json.dumps(payload, indent=2))
    md_path = out_dir / f"source_probe_{revision}.md"
    md_path.write_text(render_markdown(payload))

    print(f"\nWrote {json_path}")
    print(f"Wrote {md_path}")

    total = append_history(results, generated_at, revision)
    print(f"Appended {len(results)} history rows (total {total}) to {HISTORY_PATH}")
    return 0


def render_markdown(payload: dict) -> str:
    rev = payload["git_revision"]
    lines = [
        f"# Keyless source live probe — {rev}",
        "",
        f"Generated `{payload['generated_at']}` · git `{rev}`",
        "",
        "Single-shot probe (1 request per source, no retries, synthetic non-PII",
        "identifiers). `reachable-no-data` means the source answered but returned",
        "nothing for the synthetic identifier — the identifier may legitimately not",
        "exist there. Host status 403/429 = reachable but blocked (evidence).",
        "",
        "## Totals",
        "",
        f"- Verified live: **{payload['totals']['verified_live']}**",
        f"- Reachable, no data: **{payload['totals']['reachable_no_data']}**",
        f"- Failed: **{payload['totals']['failed']}**",
        f"- Skipped: **{payload['totals']['skipped']}**",
        "",
        "## Per-source results",
        "",
        "| module | kind | id type | verdict | host | leaks | func latency (ms) | notes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(payload["results"], key=lambda x: x["verdict"]):
        host = str(r["host"]["status_code"]) if r["host"]["status_code"] is not None else "-"
        if r["host"]["error"]:
            host = f"err:{r['host']['error'][:60]}"
        lat = r["functional"]["latency_ms"]
        note = r["skipped_reason"] or r["functional"]["error"] or ""
        samples = r["functional"]["samples"]
        if samples:
            note = f"e.g. {samples[0]['text'][:70]}"
        lines.append(
            f"| {r['module']} | {r['kind']} | {r['identifier_type'] or '-'} | "
            f"{r['verdict']} | {host} | {r['functional']['leak_count']} | "
            f"{lat if lat is not None else '-'} | {note[:100]} |"
        )
    lines.append("")
    return "\n".join(lines)


def load_history() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    try:
        data = json.loads(HISTORY_PATH.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        # Never let a corrupt history file block a sweep.
        return []


def append_history(results: list[dict], probed_at: str, revision: str) -> int:
    """Append one history row per probed source, keyed like probe_one + verdict."""
    history = load_history()
    for row in results:
        entry: dict[str, Any] = {"probed_at": probed_at, "git_revision": revision}
        for key in (
            "module",
            "source_class",
            "kind",
            "identifier_type",
            "identifier",
            "skipped_reason",
            "host",
            "functional",
            "verdict",
        ):
            entry[key] = row.get(key)
        history.append(entry)
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(history, indent=2))
    return len(history)


def failure_class(row: dict) -> str | None:
    """Classify a failed probe: http-404 / http-429 / http-403 / connection / parse / other."""
    if row.get("verdict") != "failed":
        return None
    host = row.get("host") or {}
    code = host.get("status_code")
    if code in (404, 429, 403):
        return f"http-{code}"
    err = host.get("error") or ""
    if not err:
        err = (row.get("functional") or {}).get("error") or ""
    low = err.lower()
    if "connect" in low:
        return "connection"
    if "parse" in low:
        return "parse"
    return "other"


def module_stats(rows: list[dict]) -> dict[str, Any]:
    probes = len(rows)
    skipped = sum(r.get("verdict") == "skipped" for r in rows)
    ns = probes - skipped
    verified = sum(r.get("verdict") == "verified-live" for r in rows)
    reachable = sum(r.get("verdict") == "reachable-no-data" for r in rows)
    failed = sum(r.get("verdict") == "failed" for r in rows)
    uptime = round(100.0 * (verified + reachable) / ns, 1) if ns else None
    classes = sorted({c for r in rows if (c := failure_class(r)) is not None})
    latest = rows[-1].get("verdict")
    if ns == 0:
        status = "skipped-only"
    elif uptime == 100:
        status = "ok"
    elif probes >= 2:
        status = "degraded"
    else:
        status = "insufficient-data"
    return {
        "probes": probes,
        "skipped": skipped,
        "verified": verified,
        "reachable": reachable,
        "failed": failed,
        "uptime": uptime,
        "classes": classes,
        "latest": latest,
        "status": status,
    }


def _span_str(history: list[dict]) -> str:
    times = sorted(p for p in (r.get("probed_at") for r in history) if p)
    if not times:
        return "?"
    return f"{str(times[0])[:19]}Z → {str(times[-1])[:19]}Z"


def render_uptime_report(history: list[dict]) -> str:
    if not history:
        return (
            "# Keyless source uptime report\n\n"
            "No history yet — run `python scripts/source_baseline.py` to collect "
            "the first live probe sweep.\n"
        )

    by_module: dict[str, list[dict]] = {}
    by_kind: dict[str, list[dict]] = {}
    for row in history:
        by_module.setdefault(str(row.get("module")), []).append(row)
        by_kind.setdefault(str(row.get("kind") or "unknown"), []).append(row)

    class_totals: Counter[str] = Counter()
    for r in history:
        c = failure_class(r)
        if c:
            class_totals[c] += 1

    non_skipped = [r for r in history if r.get("verdict") != "skipped"]
    up = [r for r in non_skipped if r.get("verdict") != "failed"]
    overall = round(100.0 * len(up) / len(non_skipped), 1) if non_skipped else None
    stats = {m: module_stats(rows) for m, rows in by_module.items()}
    degraded = sorted(m for m, s in stats.items() if s["status"] == "degraded")

    lines = [
        "# Keyless source uptime report",
        "",
        f"Generated `{datetime.now(timezone.utc).isoformat()}`",
        "",
        f"- History rows: **{len(history)}**",
        f"- Runs span: {_span_str(history)}",
        f"- Overall uptime (non-skipped probes): **{overall if overall is not None else '-'}%**",
        f"- Degraded sources (≥2 probes, uptime < 100%): **{len(degraded)}**"
        + (f" — {', '.join(degraded)}" if degraded else ""),
        "",
        "Definitions: uptime = share of non-skipped probes where the source answered",
        "(verdict `verified-live` or `reachable-no-data`, i.e. not `failed`).",
        "`insufficient-data` = a single non-skipped probe failed (likely a flake).",
        "",
        "## Failure-class breakdown (all failed probes)",
        "",
        "| failure class | count |",
        "|---|---|",
    ]
    for cls, cnt in class_totals.most_common():
        lines.append(f"| {cls} | {cnt} |")

    lines += [
        "",
        "## Hit rates by category",
        "",
        "| kind | probes | verified-live | hit rate % |",
        "|---|---|---|---|",
    ]
    for kind in sorted(by_kind):
        rows = by_kind[kind]
        verified = sum(r.get("verdict") == "verified-live" for r in rows)
        ns = sum(r.get("verdict") != "skipped" for r in rows)
        rate = round(100.0 * verified / ns, 1) if ns else None
        lines.append(f"| {kind} | {len(rows)} | {verified} | {rate if rate is not None else '-'} |")

    lines += [
        "",
        "## Per-source",
        "",
        "| source | probes | verified | reachable | failed | skipped | uptime % | failure classes | latest | status |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for module in sorted(by_module):
        s = stats[module]
        uptime = f"{s['uptime']}" if s["uptime"] is not None else "-"
        classes = ", ".join(s["classes"]) or "-"
        lines.append(
            f"| {module} | {s['probes']} | {s['verified']} | {s['reachable']} | "
            f"{s['failed']} | {s['skipped']} | {uptime} | {classes} | "
            f"{s['latest']} | {s['status']} |"
        )
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
