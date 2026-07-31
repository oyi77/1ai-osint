# Modules

1ai-osint ships a modular set of OSINT scanners. Modules are dispatched by the
deep scan engine and are individually addressable from the CLI
(`1ai-osint scan --module <name>`).

## Module list

The `scan` command accepts the following module names
(`src/cli/app.py`):

| Module | Purpose |
| --- | --- |
| `gitleaks` | Scan repositories / paths for leaked secrets (Gitleaks Scanner). |
| `data_leaks` | Aggregated breach/leak lookup across 13+ sources (HIBP, DeHashed, Scylla, LeakCheck, BreachDirectory, Snusbase, IntelX, and more). |
| `people` | Username / handle enumeration across social platforms (Sherlock-powered). |
| `phone` | Phone number OSINT (carrier, location, and connected identifiers). |
| `crypto_passphrase` | BIP-39 passphrase / mnemonic analysis. |
| `crypto_privatekey` | Private-key derivation and analysis. |
| `crypto_balance` | Balance scanning across BTC, ETH, SOL, and TRON (targeted, random, leak, or smart mode). |
| `domain` | Domain intelligence. |
| `email` | Email intelligence. |
| `social` | Social media OSINT. |
| `all` | Run every available module. |

## Deep scan modules

The `deep_scan` command activates a subset of modules per profile (`fast`,
`standard`, `deep` — see `src/modules/deep_scan/scan_profiles.py`). Modules
are routed by identifier type (name, email, username, phone, NIK, crypto
address) via the engine's input registry. Notable deep-scan capabilities
include:

- **Leak finder** — continuous/one-shot discovery of leaked crypto keys and
  mnemonics from GitHub, paste sites, Telegram, Reddit, and Twitter
  (`src/modules/crypto/leak_finder/`).
- **Crypto tracing** — blockchain transaction tracing (`BlockchainTxTracer`).
- **AI enrichment** — Phase 5 evidence enrichment via the AI orchestrator.
- **External tool intel** — optional wrappers over recon CLIs (theHarvester,
  amass, subfinder, bbot, spiderfoot, chiasmodon CLI, and others), gated on
  tool availability.

## Data leak sources

The data-leaks aggregator discovers sources through
`src/modules/sources.py`. Source keys configured in `.env` include:

- Have I Been Pwned (`HIBP_API_KEY`)
- Shodan (`SHODAN_API_KEY`)
- VirusTotal (`VIRUSTOTAL_API_KEY`)
- AbuseIPDB (`ABUSEIPDB_API_KEY`)
- WhoisXML (`WHOISXML_API_KEY`)
- Chiasmodon (`CHIASMODON_TOKEN`)
- DeHashed (`DEHASHED_API_KEY`)
- Scylla (`SCYLLA_API_KEY`)
- LeakCheck (`LEAKCHECK_API_KEY`)
- BreachDirectory (`BREACHDIRECTORY_API_KEY`)
- Snusbase (`SNUSBASE_API_KEY`)
- IntelX (`INTELX_API_KEY`)

## Other subsystems

- **ZKIT identity tracking** (`identity_tracking`) — privacy-preserving
  identity graph with salted hashing.
- **Gitleaks** — repository secret scanning.
- **Distributed nodes** — worker `node` agents coordinated by a Telegram
  `master` bot.
- **Plugin system** — user-registered plugins discovered at runtime.

Use `1ai-osint modules` to list the modules available in your installation.
