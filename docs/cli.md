# CLI

The `1ai-osint` command-line interface is built with Typer
(`src/cli/app.py`). Command modules are registered via `@app.command()`
decorators and import at startup from `src/cli/main.py`.

```text
Usage: 1ai-osint [OPTIONS] COMMAND [ARGS]...
```

## Global options

Provided by the app callback (`@app.callback(invoke_without_command=True)` in
`src/cli/main.py`):

| Option | Default | Description |
| --- | --- | --- |
| `--log-format` | `text` | Log format: `text` or `json`. |
| `--log-level` | — | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |

## Command reference

### `version`

Show the installed version.

### `doctor`

Check the environment: Python version, `sherlock` availability, breach API
keys, and configured providers. Prints a report.

### `modules`

List all available OSINT modules.

### `plugins`

List all registered plugins (via `PluginRegistry.discover()`).

### `web`

Start the 1ai-osint Web UI dashboard server — a FastAPI application with a
dashboard, entity browser, report viewer, and timeline visualization.

| Option | Default | Description |
| --- | --- | --- |
| `--port` / `-p` | `8080` | Port to bind the web server to. |
| `--host` / `-H` | `0.0.0.0` | Host address to bind to. |

See [Web UI](web-ui.md) for routes and authentication.

### `scan`

Run an OSINT scan against a target.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `target` (arg) | `random` | Target: URL, path, email, mnemonic, or `random` for a random scan. |
| `--module` | `all` | Module to use: `gitleaks`, `data_leaks`, `people`, `phone`, `crypto_passphrase`, `crypto_privatekey`, `crypto_balance`, `domain`, `email`, `social`, `all`. |
| `--output` | `json` | Output format: `json`, `sarif`, `pdf`. |
| `--ai` | off | Enable AI analysis via the orchestrator. |
| `--zkit` | off | Enable ZKIT identity tracking. |
| `--zkit-salt` | — | ZKIT salt for privacy-preserving identity hashing. |
| `--timeout` | `300` | Scan timeout in seconds. |
| `--scan-mode` | auto | Crypto-balance mode: `random`, `targeted`, `leak`, or `smart`. |
| `--workers` | `20` | Concurrent workers for random scan. |
| `--duration` | `0` | Duration in seconds for random scan (0 = use iterations). |
| `--account-count` | `1` | Accounts to derive per chain. |
| `--min-balance` | `0.0` | Minimum balance threshold for random-scan hits. |

### `deep_scan`

Deep scan — recursive identity investigation across all modules.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `target` (arg) | required | Target to investigate (name, email, username, phone, NIK). |
| `--format` / `-f` | `html` | Output format: `html`, `json`, `stix`. |
| `--output` / `-o` | — | Output file path. |
| `--max-iterations` | `5` | Max recursive scan iterations. |
| `--timeout` | `30` | Timeout per module in seconds. |
| `--fast` | off | Shortcut for `--profile fast`. |
| `--profile` / `-p` | `standard` | Collection profile: `fast`, `standard`, `deep` (see `docs/INTEL_STANDARD.md`). |
| `--case` | — | Investigation case ID (persists under `investigations/`). |
| `--ai` | off | Enhance BLUF with AI when an API key is configured. |
| `--pdf` | off | Also write a briefing PDF. |
| `--budget` | `15.0` | Execution budget for external APIs (0 = unlimited). |

The engine caps `--max-iterations` at the profile limit and resolves profile
timeouts automatically. With `--case`, a delta briefing is computed against
the previous run of the same case.

### `zkit-deep-scan`

ZKIT-enabled deep scan.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `target` (arg) | required | Target identifier (Name, Username, Email, Phone, Domain). |
| `--max-iterations` | `5` | Maximum recursive search depth. |
| `--fast` | off | Use fast profile mode (lower timeouts, fewer handles). |

### `report`

Generate a report for a target.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `target` (arg) | required | Target to generate report for. |
| `--output` | `html` | Output format: `html`, `json`. |
| `--module` | `all` | Module to scan first, or `all`. |

### `report_from_file`

Generate a report from an existing JSON report file.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `report_file` (arg) | required | Path to JSON report file. |
| `--output` | `html` | Output format: `html`, `json`. |

### `resolve`

Resolve an identity — find all connected entities across all sources.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `input` (arg) | required | Identifier to resolve (email, username, phone, crypto address). |
| `--output` | `json` | Output format: `json`, `sarif`, `pdf`. |
| `--ai` | off | Enable AI analysis. |
| `--sources` | `all` | Comma-separated source names or `all`. |
| `--timeout` | `300` | Timeout in seconds. |

### `leak_finder`

Find leaked crypto keys and mnemonics from public sources (GitHub, paste
sites, Telegram, Reddit, Twitter), check balances, and sweep funded wallets.

| Option | Default | Description |
| --- | --- | --- |
| `--continuous` / `-c` | off | Run in continuous mode (periodic scans). |
| `--address` / `-a` | — | Search for a specific wallet address. |
| `--sources` / `-s` | `github,paste,telegram,reddit,twitter` | Comma-separated sources. |
| `--interval` / `-i` | `300` | Seconds between runs in continuous mode. |
| `--github-token` | — | GitHub API token for authenticated search (higher rate limits). |

### `sweep`

Sweep funds from leaked wallets to destination addresses.

| Option | Default | Description |
| --- | --- | --- |
| `--auto` | off | Auto-sweep all funded wallets from discovered keys. |
| `--key` | — | Specific private key to sweep. |
| `--mnemonic` | — | Specific mnemonic to sweep. |
| `--chain` | `all` | Chain to sweep: `all`, `ethereum`, `solana`, `bitcoin`. |
| `--dry-run` | off | Show what would be swept without executing. |

### `monitor`

Continuously monitor an identity for new connections and leaks.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `target` (arg) | required | Identifier to monitor (email, username, crypto address). |
| `--interval` | `300` | Check interval in seconds. |
| `--sources` | `all` | Comma-separated source names or `all`. |
| `--telegram` | off | Send alerts via Telegram. |

### `node`

Run as a worker node, connecting to the master via Telegram.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `action` (arg) | required | Action: `start`, `status`. |
| `--node-id` | hostname | Node identifier. |
| `--master-chat-id` | — | Master Telegram chat ID. |
| `--api-port` | `8420` | HTTP API port. |

Requires `TELEGRAM_BOT_TOKEN` and `MASTER_CHAT_ID` (or `--master-chat-id`).

### `master`

Run as the master bot, controlling all nodes via Telegram.

| Argument / Option | Default | Description |
| --- | --- | --- |
| `action` (arg) | required | Action: `start`, `status`. |
| `--allowed-chat-ids` | — | Comma-separated allowed Telegram chat IDs. |

Requires `TELEGRAM_BOT_TOKEN` (falls back to `TELEGRAM_CHAT_ID` for allowed
chat IDs).
