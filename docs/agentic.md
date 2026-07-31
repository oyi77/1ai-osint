# Agentic Layer (MCP + Agent Loop)

Blueprint Phase 1 adds two agentic surfaces to the platform: an **MCP server**
(S3) that exposes the existing pipeline to any MCP-capable client, and a
**thin agent loop** (S4) that plans and self-corrects a scan.

## MCP bridge — `src/mcp_bridge/server.py`

A FastMCP server (`mcp` SDK 1.x) exposing three tools over stdio:

| Tool | Description |
| --- | --- |
| `search(target, source_filter=None)` | Runs `run_source_scan()` over the requested sources (or the full registry) and feeds results into `CrossModuleCorrelator.correlate()`. Returns findings + correlation graph stats. |
| `list_sources()` | Lists all registered source adapters. |
| `source_compliance(source)` | Returns the UU PDP legal basis / retention / consent posture for a source. |

The bridge **delegates** — it re-implements no scanning or correlation
logic. Compliance is inherited: every adapter call goes through the same
legal-basis gate and audit log as the CLI/engine paths.

### Why `mcp_bridge` and not `mcp`?

The official SDK package is named `mcp`. A local `src/mcp/` package would
shadow it whenever `src/` is on `sys.path` (e.g. under pytest), breaking
`import mcp.server.*`. The package is named `mcp_bridge` to stay unambiguous.

### Run

```bash
uv run python -m src.mcp_bridge.server   # stdio transport
```

Connect any MCP client (Claude Desktop, Claude Code `--mcp-config`, …).

### Test

```bash
uv run pytest tests/unit/test_mcp_server.py -q
```

Tests drive a real in-process MCP handshake over memory streams
(initialize → list tools → call tools) — no network, no subprocess.

## Thin agent loop — `src/modules/deep_scan/agent_loop.py`

One input → rule-based planner → structured report:

1. `detect_target_type(target)` classifies the input (email / phone /
   username / domain / name / crypto address).
2. The planner maps the type to an ordered source plan (primary sources
   first, alternates after).
3. The **primary wave** runs concurrently (up to 3 sources).
4. Rate-limited or errored sources trigger the **fallback wave**: alternate
   sources run in batches until enough succeed.
5. Compliance gate: consent-required sources (UU PDP Pasal 4.2) are blocked
   pre-run unless explicitly allowed.
6. Every adapter call is audited (same JSONL audit log as Phase 0).

### Usage

```python
from src.modules.deep_scan.agent_loop import run_agent_scan

report = await run_agent_scan("victim@example.com", max_sources=12)
print(report.total_findings, [s.source for s in report.steps if s.ok])
```

### Benchmark

`scripts/benchmark_agent_vs_batch.py` compares the agent loop against the
naive "run every adapter" batch in a deterministic, mocked environment:

```text
Naive batch        : attempted=19 ok=16 errors= 3 elapsed=  2.01s
Agent loop (S4)    : attempted= 6 ok= 3 failed= 3 deferred= 2 elapsed=  0.32s

Wall-clock speedup : 6.22x
Sources touched    : 6 vs 19 (13 unnecessary calls avoided)
```

The agent loop touches only what the planner deems relevant and pivots on
failure — the naive batch pays full latency for every source, including
the ones that rate-limit it.
