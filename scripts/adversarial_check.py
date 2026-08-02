#!/usr/bin/env python
"""Adversarial verification receipts (Gap 1).

Proves the safety boundaries of the engine against hostile input, with
machine- and human-readable receipts:

1. SSRF guard — private/loopback/link-local/metadata/numeric-alias targets
   are rejected; public IPs, unresolvable hostnames and plain identifiers
   pass. Without this an operator could turn the scanner into an SSRF proxy.
2. Web auth fail-closed — ``require_tier`` returns 403 when no tier was
   resolved (auth disabled / middleware not run), never allow-by-default.
3. Hostile identifiers — hostile usernames/domains (``../etc``, ``<script>``,
   quotes) are accepted as *identifiers* (scanning them is legitimate OSINT)
   while host-like private targets stay blocked by the SSRF guard.

Usage:
    uv run python scripts/adversarial_check.py [--out docs/evidence/audit]

Exits 0 only when every assertion passes; writes receipts on success.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1. SSRF guard
# ---------------------------------------------------------------------------

BLOCKED: list[tuple[str, str]] = [
    ("127.0.0.1:8080", "loopback IP literal"),
    ("http://127.0.0.1/", "loopback inside URL"),
    ("169.254.169.254", "AWS/GCP metadata link-local"),
    ("10.0.0.1", "RFC1918 private"),
    ("192.168.1.1", "RFC1918 private"),
    ("172.16.0.1", "RFC1918 private"),
    ("0.0.0.0", "unspecified"),
    ("2130706433", "decimal loopback alias (inet_aton)"),
    ("0x7f000001", "hex loopback alias"),
    ("localhost", "blocked hostname"),
    ("metadata.google.internal", "cloud metadata hostname"),
    ("[::1]:8080", "IPv6 loopback"),
]

ALLOWED: list[tuple[str, str]] = [
    ("https://8.8.8.8/x", "public IP"),
    ("example.com", "public hostname (DNS-resolvable)"),
    ("john_doe", "plain username — not host-like"),
    ("0xdeadbeef@example.org", "email → public domain"),
    ("+6281234567890", "phone number"),
    ("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "crypto address"),
]

HOSTILE_IDENTIFIERS: list[str] = [
    "../etc",
    "<script>alert(1)</script>",
    "foo' OR '1'='1",
    'evil"@example.com',
    "..%2f..%2fetc/passwd",
]

# ---------------------------------------------------------------------------
# 2. Auth fail-closed
# ---------------------------------------------------------------------------


def _auth_fail_closed() -> dict:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from src.core.rbac import AccessTier
    from src.web.auth import require_tier

    app = FastAPI()

    @app.get("/admin-only")
    async def admin_only(_: None = Depends(require_tier(AccessTier.ADMIN))):
        return {"ok": True}

    # No AuthMiddleware, no token: scope has no auth_tier → must 403.
    with TestClient(app) as client:
        response = client.get("/admin-only")
    return {"status_code": response.status_code, "expected": 403}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="docs/evidence/audit", help="receipt dir")
    args = parser.parse_args()

    from src.core.ssrf_guard import validate_scan_target

    checks: list[dict] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append(
            {
                "name": name,
                "passed": bool(passed),
                "detail": detail,
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            }
        )

    for target, why in BLOCKED:
        check(f"ssrf_block:{target}", not validate_scan_target(target), f"{target!r} is {why} — must be rejected")

    for target, why in ALLOWED:
        check(f"ssrf_allow:{target}", validate_scan_target(target), f"{target!r} ({why}) — must be allowed")

    for ident in HOSTILE_IDENTIFIERS:
        # Identifiers themselves are valid scan subjects (hostile-looking is
        # not a reason to refuse a username/domain lookup) — the *guard* is
        # that any host-like private target inside them stays blocked.
        check(
            f"ident_accept:{ident[:24]}",
            validate_scan_target(ident),
            f"hostile-looking identifier {ident!r} accepted as scan subject",
        )

    auth = _auth_fail_closed()
    check(
        "auth_fail_closed",
        auth["status_code"] == auth["expected"],
        f"require_tier(ADMIN) with no resolved tier → {auth['status_code']}, "
        f"expected {auth['expected']} (fail closed)",
    )

    passed = all(c["passed"] for c in checks)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    payload: dict[str, Any] = {
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "engine": "1ai-osint internal adversarial gate",
        "summary": {
            "checks": len(checks),
            "passed": sum(1 for c in checks if c["passed"]),
            "failed": sum(1 for c in checks if not c["passed"]),
        },
        "verdict": "PASS" if passed else "FAIL",
        "checks": checks,
    }
    (out_dir / f"adversarial_{stamp}.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Adversarial verification receipt — {stamp}",
        "",
        f"Verdict: **{'PASS' if passed else 'FAIL'}** "
        f"({payload['summary']['passed']}/{payload['summary']['checks']} checks)",
        "",
        "| check | passed | detail |",
        "|---|---|---|",
    ]
    for c in checks:
        lines.append(f"| {c['name']} | {'✅' if c['passed'] else '❌'} | {c['detail']} |")
    lines.append("")
    lines.append(
        "Generated by `scripts/adversarial_check.py` — internal gate only; "
        "not a substitute for a third-party security audit."
    )
    (out_dir / f"adversarial_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        f"adversarial gate: {'PASS' if passed else 'FAIL'} "
        f"({payload['summary']['passed']}/{payload['summary']['checks']}) — "
        f"receipts in {out_dir}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
