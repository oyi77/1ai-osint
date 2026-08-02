# Keyless source uptime report

Generated `2026-08-02T01:54:39.719829+00:00`

- History rows: **126**
- Runs span: 2026-08-02T01:16:03Z → 2026-08-02T01:54:26Z
- Overall uptime (non-skipped probes): **76.0%**
- Degraded sources (≥2 probes, uptime < 100%): **13** — bgpview, certspotter, codeberg, darknet, discord, github, mastodon, paste, reddit, rss, s3, telegram, twitter

Definitions: uptime = share of non-skipped probes where the source answered
(verdict `verified-live` or `reachable-no-data`, i.e. not `failed`).
`insufficient-data` = a single non-skipped probe failed (likely a flake).

## Failure-class breakdown (all failed probes)

| failure class | count |
|---|---|
| other | 22 |
| connection | 3 |

## Hit rates by category

| kind | probes | verified-live | hit rate % |
|---|---|---|---|
| api | 8 | 4 | 50.0 |
| re | 84 | 46 | 54.8 |
| scrape | 12 | 4 | 33.3 |
| tool | 22 | 0 | - |

## Per-source

| source | probes | verified | reachable | failed | skipped | uptime % | failure classes | latest | status |
|---|---|---|---|---|---|---|---|---|---|
| amass | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| anubis | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| bbot | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| bgpview | 2 | 0 | 0 | 2 | 0 | 0.0 | connection | failed | degraded |
| blockchair | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| cargo | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| certspotter | 2 | 0 | 1 | 1 | 0 | 50.0 | connection | reachable-no-data | degraded |
| chess | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| codeberg | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| codeforces | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| darknet | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| devto | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| discord | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| dns_records | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| dnsdumpster | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| duckduckgo | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| etherscan | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| fandom | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| feodo | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| github | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| h8mail | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| hackertarget | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| holehe | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| httpx | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| huggingface | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| ip_api | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| ipinfo | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| itchio | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| keybase | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| letterboxd | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| maigret | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| malwarebazaar | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| mastodon | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| medium | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| mempool | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| nmap | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| npm | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| paste | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| pastebin | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| pgp_keys | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| phoneinfoga | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| proxynova | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| pulsedive | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| pypi | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| rapiddns | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| reddit | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| rss | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| rubygems | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| s3 | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| scratch | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| sherlock | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| social | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| stackoverflow | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| steam | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| subfinder | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| telegram | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| theharvester | 2 | 0 | 0 | 0 | 2 | - | - | skipped | skipped-only |
| threatfox | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| twitter | 2 | 0 | 0 | 2 | 0 | 0.0 | other | failed | degraded |
| urlscan | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| veriphone | 2 | 0 | 2 | 0 | 0 | 100.0 | - | reachable-no-data | ok |
| whatsmyname | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
| youtube | 2 | 2 | 0 | 0 | 0 | 100.0 | - | verified-live | ok |
