# Keyless source live probe — f73d4f2

Generated `2026-08-02T01:16:03.013793+00:00` · git `f73d4f2`

Single-shot probe (1 request per source, no retries, synthetic non-PII
identifiers). `reachable-no-data` means the source answered but returned
nothing for the synthetic identifier — the identifier may legitimately not
exist there. Host status 403/429 = reachable but blocked (evidence).

## Totals

- Verified live: **27**
- Reachable, no data: **12**
- Failed: **13**
- Skipped: **11**

## Per-source results

| module | kind | id type | verdict | host | leaks | func latency (ms) | notes |
|---|---|---|---|---|---|---|---|
| mastodon | TransportKind.RE | username | failed | - | 0 | 4338 |  |
| telegram | TransportKind.RE | username | failed | - | 0 | 228 |  |
| reddit | TransportKind.RE | username | failed | - | 0 | 8515 |  |
| bgpview | TransportKind.RE | ip | failed | err:ConnectError: [Errno -2] Name or service not known | 0 | 20 |  |
| codeberg | TransportKind.RE | username | failed | - | 0 | 5450 |  |
| rss | TransportKind.RE | domain | failed | - | 0 | 8356 |  |
| s3 | TransportKind.RE | domain | failed | - | 0 | 4793 |  |
| twitter | TransportKind.RE | username | failed | - | 0 | 847 |  |
| certspotter | TransportKind.RE | domain | failed | err:ConnectTimeout:  | 0 | 15016 | TimeoutError: exceeded 15.0s |
| discord | TransportKind.SCRAPE | domain | failed | - | 0 | 171 |  |
| darknet | TransportKind.SCRAPE | domain | failed | - | 0 | 0 |  |
| paste | TransportKind.SCRAPE | username | failed | - | 0 | 12904 |  |
| github | TransportKind.API | domain | failed | - | 0 | 15010 | TimeoutError: exceeded 15.0s |
| medium | TransportKind.RE | username | reachable-no-data | 403 | 0 | 1461 |  |
| feodo | TransportKind.RE | ip | reachable-no-data | 301 | 0 | 129 |  |
| anubis | TransportKind.RE | domain | reachable-no-data | 301 | 0 | 478 |  |
| malwarebazaar | TransportKind.RE | hash | reachable-no-data | 301 | 0 | 1898 |  |
| veriphone | TransportKind.RE | phone | reachable-no-data | 200 | 0 | 365 |  |
| pgp_keys | TransportKind.RE | email | reachable-no-data | 400 | 0 | 639 |  |
| proxynova | TransportKind.RE | username | reachable-no-data | 200 | 0 | 814 |  |
| blockchair | TransportKind.RE | crypto_address | reachable-no-data | 200 | 0 | 6215 |  |
| threatfox | TransportKind.RE | domain | reachable-no-data | 301 | 0 | 725 |  |
| steam | TransportKind.RE | username | reachable-no-data | 200 | 0 | 331 |  |
| dnsdumpster | TransportKind.SCRAPE | domain | reachable-no-data | 200 | 0 | 134 |  |
| etherscan | TransportKind.API | crypto_address | reachable-no-data | 200 | 0 | 1026 |  |
| subfinder | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| theharvester | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| nmap | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| bbot | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| maigret | TransportKind.TOOL | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| h8mail | TransportKind.TOOL | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| holehe | TransportKind.TOOL | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| httpx | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| phoneinfoga | TransportKind.TOOL | phone | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| amass | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| sherlock | TransportKind.TOOL | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| devto | TransportKind.RE | username | verified-live | 200 | 4 | 419 | e.g. devto: octocat |
| urlscan | TransportKind.RE | domain | verified-live | 404 | 61 | 1238 | e.g. url: https://classichomewaregifts.com.au/ |
| social | TransportKind.RE | username | verified-live | - | 2 | 7859 | e.g. {'login': 'octocat', 'id': 583231, 'node_id': 'MDQ6VXNlcjU4MzIzMQ==',  |
| cargo | TransportKind.RE | username | verified-live | 403 | 5 | 932 | e.g. KODEGEN.ᴀɪ: Memory-efficient, Blazing-Fast, MCP tools for code generat |
| stackoverflow | TransportKind.RE | username | verified-live | - | 30 | 434 | e.g. After creating pull request to &quot;octocat/Spoon-Knife&quot;, what i |
| dns_records | TransportKind.RE | domain | verified-live | 400 | 9 | 10045 | e.g. A 104.20.23.154 (TTL 300) |
| letterboxd | TransportKind.RE | username | verified-live | 403 | 3 | 556 | e.g. letterboxd: octocat |
| itchio | TransportKind.RE | username | verified-live | 200 | 2 | 462 | e.g. itchio: octocat |
| pastebin | TransportKind.RE | username | verified-live | 200 | 3 | 424 | e.g. pastebin: octocat |
| codeforces | TransportKind.RE | username | verified-live | 200 | 5 | 323 | e.g. codeforces: octocat |
| hackertarget | TransportKind.RE | domain | verified-live | 200 | 2 | 3252 | e.g. example.com -> 104.20.23.154 |
| rapiddns | TransportKind.RE | domain | verified-live | 200 | 3 | 1031 | e.g. example.com |
| youtube | TransportKind.RE | username | verified-live | 200 | 3 | 539 | e.g. youtube: octocat |
| rubygems | TransportKind.RE | username | verified-live | 404 | 5 | 894 | e.g. Command line github |
| pypi | TransportKind.RE | username | verified-live | 200 | 1 | 353 | e.g. Octocat
#######

.. _description:

Octocat -- Python client for Github |
| huggingface | TransportKind.RE | username | verified-live | 200 | 2 | 629 | e.g. huggingface: octocat |
| mempool | TransportKind.RE | crypto_address | verified-live | 308 | 12 | 2149 | e.g. Address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa — funded 5732462210 sats, s |
| ip_api | TransportKind.RE | ip | verified-live | 200 | 15 | 76 | e.g. status: success |
| scratch | TransportKind.RE | username | verified-live | 200 | 1 | 938 | e.g. scratch: octocat |
| chess | TransportKind.RE | username | verified-live | 200 | 3 | 590 | e.g. chess: octocat |
| keybase | TransportKind.RE | username | verified-live | 200 | 4 | 761 | e.g. keybase: octocat |
| npm | TransportKind.RE | username | verified-live | - | 9 | 10280 | e.g. # octocat-images
[![npm version](https://badge.fury.io/js/octocat-imag |
| fandom | TransportKind.RE | username | verified-live | 403 | 5 | 339 | e.g. fandom: octocat |
| duckduckgo | TransportKind.SCRAPE | domain | verified-live | - | 3 | 10105 | e.g. <!DOCTYPE html>
<html class="client-nojs vector-feature-language-in-he |
| whatsmyname | TransportKind.SCRAPE | username | verified-live | 302 | 1 | 599 | e.g. Username 'octocat' found on WhatsMyName results page |
| pulsedive | TransportKind.API | domain | verified-live | 301 | 1 | 924 | e.g. Indicator: example.com
Risk: none
Threats: [{'tid': 235, 'name': 'Adpo |
| ipinfo | TransportKind.API | ip | verified-live | 200 | 1 | 304 | e.g. IP: 8.8.8.8
City: Mountain View
Region: California
Country: US
Org: AS |
