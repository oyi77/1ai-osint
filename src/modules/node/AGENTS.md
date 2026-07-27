<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 -->

# node

## Purpose
Distributed node management — multi-agent OSINT architecture with master/agent protocol for distributed scanning.

## Key Files
| File | Description |
|------|-------------|
| `master.py` | Master node — job distribution and coordination |
| `master_api.py` | Master node REST API |
| `agent.py` | Agent node — executes assigned scan jobs |
| `active_monitor.py` | Active monitoring and health checks |
| `protocol.py` | Master-agent communication protocol |
| `db.py` | Node-local database for job results |
| `__init__.py` | Package initializer |

## For AI Agents

### Working In This Directory
- Master distributes scan tasks to registered agents
- Agents report results back to master
- Protocol uses JSON over HTTP

## Dependencies

### Internal
- `src/core/` — models, config
- `src/modules/` — scan module implementations

<!-- MANUAL: -->
