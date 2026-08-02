# Keyless source live probe — 5467b0a

Generated `2026-08-02T01:54:26.196296+00:00` · git `5467b0a`

Single-shot probe (1 request per source, no retries, synthetic non-PII
identifiers). `reachable-no-data` means the source answered but returned
nothing for the synthetic identifier — the identifier may legitimately not
exist there. Host status 403/429 = reachable but blocked (evidence).

## Totals

- Verified live: **27**
- Reachable, no data: **13**
- Failed: **12**
- Skipped: **11**

## Per-source results

| module | kind | id type | verdict | host | leaks | func latency (ms) | notes |
|---|---|---|---|---|---|---|---|
| reddit | TransportKind.RE | username | failed | - | 0 | 9262 |  |
| codeberg | TransportKind.RE | username | failed | - | 0 | 5639 |  |
| rss | TransportKind.RE | domain | failed | - | 0 | 8354 |  |
| bgpview | TransportKind.RE | ip | failed | err:ConnectError: [Errno -2] Name or service not known | 0 | 15 |  |
| twitter | TransportKind.RE | username | failed | - | 0 | 1148 |  |
| mastodon | TransportKind.RE | username | failed | - | 0 | 4270 |  |
| telegram | TransportKind.RE | username | failed | - | 0 | 414 |  |
| s3 | TransportKind.RE | domain | failed | - | 0 | 4789 |  |
| paste | TransportKind.SCRAPE | username | failed | - | 0 | 13011 |  |
| discord | TransportKind.SCRAPE | domain | failed | - | 0 | 167 |  |
| darknet | TransportKind.SCRAPE | domain | failed | - | 0 | 0 |  |
| github | TransportKind.API | domain | failed | - | 0 | 15013 | TimeoutError: exceeded 15.0s |
| feodo | TransportKind.RE | ip | reachable-no-data | 301 | 0 | 162 |  |
| pgp_keys | TransportKind.RE | email | reachable-no-data | 400 | 0 | 602 |  |
| steam | TransportKind.RE | username | reachable-no-data | 200 | 0 | 142 |  |
| threatfox | TransportKind.RE | domain | reachable-no-data | 301 | 0 | 819 |  |
| blockchair | TransportKind.RE | crypto_address | reachable-no-data | 200 | 0 | 6213 |  |
| malwarebazaar | TransportKind.RE | hash | reachable-no-data | 301 | 0 | 1902 |  |
| medium | TransportKind.RE | username | reachable-no-data | 403 | 0 | 495 |  |
| certspotter | TransportKind.RE | domain | reachable-no-data | 400 | 0 | 755 |  |
| veriphone | TransportKind.RE | phone | reachable-no-data | 200 | 0 | 348 |  |
| proxynova | TransportKind.RE | username | reachable-no-data | 200 | 0 | 823 |  |
| anubis | TransportKind.RE | domain | reachable-no-data | 301 | 0 | 240 |  |
| dnsdumpster | TransportKind.SCRAPE | domain | reachable-no-data | 200 | 0 | 110 |  |
| etherscan | TransportKind.API | crypto_address | reachable-no-data | 200 | 0 | 1023 |  |
| holehe | TransportKind.TOOL | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| nmap | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| sherlock | TransportKind.TOOL | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| amass | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| h8mail | TransportKind.TOOL | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| phoneinfoga | TransportKind.TOOL | phone | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| httpx | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| bbot | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| subfinder | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| maigret | TransportKind.TOOL | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| theharvester | TransportKind.TOOL | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| itchio | TransportKind.RE | username | verified-live | 200 | 2 | 334 | e.g. itchio: octocat |
| chess | TransportKind.RE | username | verified-live | 200 | 3 | 569 | e.g. chess: octocat |
| rubygems | TransportKind.RE | username | verified-live | 404 | 5 | 97 | e.g. Command line github |
| rapiddns | TransportKind.RE | domain | verified-live | 200 | 3 | 1265 | e.g. example.com |
| pypi | TransportKind.RE | username | verified-live | 200 | 1 | 337 | e.g. Octocat
#######

.. _description:

Octocat -- Python client for Github |
| keybase | TransportKind.RE | username | verified-live | 200 | 4 | 765 | e.g. keybase: octocat |
| codeforces | TransportKind.RE | username | verified-live | 200 | 5 | 322 | e.g. codeforces: octocat |
| mempool | TransportKind.RE | crypto_address | verified-live | 308 | 13 | 2113 | e.g. Address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa — funded 5732462756 sats, s |
| letterboxd | TransportKind.RE | username | verified-live | 403 | 3 | 523 | e.g. letterboxd: octocat |
| devto | TransportKind.RE | username | verified-live | 200 | 4 | 525 | e.g. devto: octocat |
| npm | TransportKind.RE | username | verified-live | - | 9 | 10479 | e.g. # octocat-images
[![npm version](https://badge.fury.io/js/octocat-imag |
| ip_api | TransportKind.RE | ip | verified-live | 200 | 15 | 76 | e.g. status: success |
| stackoverflow | TransportKind.RE | username | verified-live | - | 30 | 1157 | e.g. After creating pull request to &quot;octocat/Spoon-Knife&quot;, what i |
| huggingface | TransportKind.RE | username | verified-live | 200 | 2 | 602 | e.g. huggingface: octocat |
| cargo | TransportKind.RE | username | verified-live | 403 | 5 | 368 | e.g. KODEGEN.ᴀɪ: Memory-efficient, Blazing-Fast, MCP tools for code generat |
| youtube | TransportKind.RE | username | verified-live | 200 | 3 | 286 | e.g. youtube: octocat |
| urlscan | TransportKind.RE | domain | verified-live | 404 | 62 | 2382 | e.g. url: https://mainepottery.com/ |
| scratch | TransportKind.RE | username | verified-live | 200 | 1 | 448 | e.g. scratch: octocat |
| hackertarget | TransportKind.RE | domain | verified-live | 200 | 1 | 973 | e.g. www.example.com -> 172.66.147.243 |
| social | TransportKind.RE | username | verified-live | - | 2 | 7301 | e.g. {'login': 'octocat', 'id': 583231, 'node_id': 'MDQ6VXNlcjU4MzIzMQ==',  |
| pastebin | TransportKind.RE | username | verified-live | 200 | 3 | 410 | e.g. pastebin: octocat |
| dns_records | TransportKind.RE | domain | verified-live | 400 | 9 | 10052 | e.g. A 172.66.147.243 (TTL 300) |
| fandom | TransportKind.RE | username | verified-live | 403 | 5 | 313 | e.g. fandom: octocat |
| duckduckgo | TransportKind.SCRAPE | domain | verified-live | - | 3 | 10109 | e.g. <!DOCTYPE html>
<html class="client-nojs vector-feature-language-in-he |
| whatsmyname | TransportKind.SCRAPE | username | verified-live | 200 | 1 | 674 | e.g. Username 'octocat' found on WhatsMyName results page |
| ipinfo | TransportKind.API | ip | verified-live | 200 | 1 | 300 | e.g. IP: 8.8.8.8
City: Mountain View
Region: California
Country: US
Org: AS |
| pulsedive | TransportKind.API | domain | verified-live | 301 | 1 | 815 | e.g. Indicator: example.com
Risk: none
Threats: [{'tid': 235, 'name': 'Adpo |
