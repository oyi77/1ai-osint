---
scope: node
depends_on:
  - src/core
status: complete
---
<!-- Parent: ../AGENTS.md -->

# node

> Last updated: document master/agent protocol, db API, and master API auth posture (commit 8fa2bbf)

## Purpose
Distributed node management — multi-agent OSINT architecture with master/agent protocol for distributed scanning.

## Key Files
| File | Description |
|------|-------------|
| `master.py` | `MasterBot` (line 29) — master node, job distribution and coordination |
| `master_api.py` | FastAPI app "1ai-osint Master API" (line 85); endpoints: health, report_keys, get_seen, acquire/release_lock, heartbeat, get/set_sources, report_sweep, get_stats, get_audit, get_nodes, enqueue_command, claim_commands |
| `agent.py` | `NodeAgent` (line 26) — agent node, executes assigned scan jobs |
| `active_monitor.py` | `ActiveMonitorDaemon` (line 19) — active monitoring and health checks |
| `protocol.py` | `MessageType`, `CommandType`, `NodeMessage`, `NodeStatus` — master-agent communication protocol |
| `db.py` | SQLite node-local database — keys, sweeps, heartbeats, audit trail, command queue (see `init_db` line 39, `enqueue_command` line 442, `claim_commands` line 454) |
| `__init__.py` | Exports `NodeAgent`, `MasterBot` |

## For AI Agents

### Working In This Directory
- Master distributes scan tasks to registered agents; agents report results back
- Protocol uses JSON over HTTP
- Master API auth: `require_master_token` compares against env `MASTER_API_TOKEN` via `secrets.compare_digest`; if the env var is unset the API runs unauthenticated by design (warning logged) — do not expose publicly without a token configured

## Dependencies

### Internal
- `src/core/` — models, config
- `src/modules/` — scan module implementations

<!-- MANUAL: -->
