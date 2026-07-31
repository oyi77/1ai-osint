# Getting Started

This guide walks you through installing 1ai-osint, configuring it, and running
your first investigations.

## Prerequisites

- Python **3.10+** (CI tests run on 3.12 and 3.13)
- [uv](https://docs.astral.sh/uv/) (recommended) or `pip`
- Optional external tools picked up at runtime: `sherlock` (bundled via
  `sherlock-project`), `maigret` (`pip install maigret`)

## Installation

### With uv (recommended)

```bash
uv sync
```

### With pip

```bash
pip install -e ".[dev]"
```

Both install the `1ai-osint` console entry point.

## Configuration

Copy the environment template and fill in the values you need:

```bash
cp .env.example .env
```

Only the variables you actually use are required:

- **AI enrichment** — `OMNIRoute_BASE_URL` / `OMNIRoute_API_KEY` (or the
  `OPENAI_API_KEY` fallback)
- **Breach sources** — `HIBP_API_KEY`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`,
  `CHIASMODON_TOKEN`, etc.
- **GitHub dork scanning** — `GITHUB_TOKEN`
- **ZKIT** — `ZKIT_SALT` (generate one with
  `python -c "import secrets; print(secrets.token_hex(32))"`)

See [Configuration](configuration.md) for the full reference and
[Web UI](web-ui.md) for the optional `WEB_AUTH_TOKEN`.

## Verify your environment

```bash
uv run 1ai-osint doctor
```

`doctor` checks the Python environment, the presence of `sherlock`, breach
source API keys, and configured providers.

## Your first scan

List the available modules:

```bash
uv run 1ai-osint modules
```

Run a one-shot scan against a target (URL, path, email, mnemonic, or `random`):

```bash
uv run 1ai-osint scan "target@example.com"
```

Run a recursive identity investigation with the default (standard) profile:

```bash
uv run 1ai-osint deep-scan "Target Name"
```

See [CLI](cli.md) for the complete command reference, including profiles,
case persistence, and AI enrichment.
