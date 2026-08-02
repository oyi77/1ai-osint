# Keyless source uptime report

Generated `2026-08-02T01:16:09.044877+00:00`

- History rows: **63**
- Runs span: 2026-08-02T01:16:03Z → 2026-08-02T01:16:03Z
- Overall uptime (non-skipped probes): **75.0%**
- Degraded sources (≥2 probes, uptime < 100%): **0**

Definitions: uptime = share of non-skipped probes where the source answered
(verdict `verified-live` or `reachable-no-data`, i.e. not `failed`).
`insufficient-data` = a single non-skipped probe failed (likely a flake).

## Failure-class breakdown (all failed probes)

| failure class | count |
|---|---|
| other | 11 |
| connection | 2 |

## Hit rates by category

| kind | probes | verified-live | hit rate % |
|---|---|---|---|
| api | 4 | 2 | 50.0 |
| re | 42 | 23 | 54.8 |
| scrape | 6 | 2 | 33.3 |
| tool | 11 | 0 | - |

## Per-source

| source | probes | verified | reachable | failed | skipped | uptime % | failure classes | latest | status |
|---|---|---|---|---|---|---|---|---|---|
| amass | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| anubis | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| bbot | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| bgpview | 1 | 0 | 0 | 1 | 0 | 0.0 | connection | failed | insufficient-data |
| blockchair | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| cargo | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| certspotter | 1 | 0 | 0 | 1 | 0 | 0.0 | connection | failed | insufficient-data |
| chess | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| codeberg | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| codeforces | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| darknet | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| devto | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| discord | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| dns_records | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| dnsdumpster | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| duckduckgo | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| etherscan | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| fandom | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| feodo | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| github | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| h8mail | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| hackertarget | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| holehe | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| httpx | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| huggingface | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| ip_api | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| ipinfo | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| itchio | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| keybase | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| letterboxd | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| maigret | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| malwarebazaar | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| mastodon | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| medium | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| mempool | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| nmap | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| npm | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| paste | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| pastebin | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| pgp_keys | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| phoneinfoga | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| proxynova | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| pulsedive | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| pypi | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| rapiddns | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| reddit | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| rss | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| rubygems | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| s3 | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| scratch | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| sherlock | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| social | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| stackoverflow | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| steam | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| subfinder | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| telegram | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| theharvester | 1 | 0 | 0 | 0 | 1 | - | - | skipped | skipped-only |
| threatfox | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| twitter | 1 | 0 | 0 | 1 | 0 | 0.0 | other | failed | insufficient-data |
| urlscan | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| veriphone | 1 | 0 | 1 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| whatsmyname | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| youtube | 1 | 1 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
