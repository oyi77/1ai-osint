# Keyless source live probe — fa3b7ae

Generated `2026-08-01T23:22:41.264027+00:00` · git `fa3b7ae`

Single-shot probe (1 request per source, no retries, synthetic non-PII
identifiers). `reachable-no-data` means the source answered but returned
nothing for the synthetic identifier — the identifier may legitimately not
exist there. Host status 403/429 = reachable but blocked (evidence).

## Totals

- Verified live: **17**
- Reachable, no data: **11**
- Failed: **12**
- Skipped: **11**

## Per-source results

| module | kind | id type | verdict | host | leaks | func latency (ms) | notes |
|---|---|---|---|---|---|---|---|
| s3 | re | domain | failed | - | 0 | 4779 |  |
| mastodon | re | username | failed | - | 0 | 4333 |  |
| codeberg | re | username | failed | - | 0 | 5473 |  |
| telegram | re | username | failed | - | 0 | 349 |  |
| twitter | re | username | failed | - | 0 | 521 |  |
| reddit | re | username | failed | - | 0 | 7830 |  |
| bgpview | re | ip | failed | err:ConnectError: [Errno -2] Name or service not known | 0 | 37 |  |
| rss | re | domain | failed | - | 0 | 8363 |  |
| discord | scrape | domain | failed | - | 0 | 181 |  |
| darknet | scrape | domain | failed | - | 0 | 0 |  |
| paste | scrape | username | failed | - | 0 | 12881 |  |
| github | api | domain | failed | - | 0 | 15010 | TimeoutError: exceeded 15.0s |
| anubis | re | domain | reachable-no-data | 301 | 0 | 204 |  |
| blockchair | re | crypto_address | reachable-no-data | 200 | 0 | 6211 |  |
| malwarebazaar | re | hash | reachable-no-data | 301 | 0 | 1911 |  |
| hackertarget | re | domain | reachable-no-data | 200 | 0 | 751 |  |
| threatfox | re | domain | reachable-no-data | 301 | 0 | 1319 |  |
| pgp_keys | re | email | reachable-no-data | 400 | 0 | 579 |  |
| feodo | re | ip | reachable-no-data | 301 | 0 | 120 |  |
| proxynova | re | username | reachable-no-data | 200 | 0 | 859 |  |
| veriphone | re | phone | reachable-no-data | 200 | 0 | 338 |  |
| dnsdumpster | scrape | domain | reachable-no-data | 200 | 0 | 103 |  |
| etherscan | api | crypto_address | reachable-no-data | 200 | 0 | 989 |  |
| maigret | tool | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| httpx | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| nmap | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| sherlock | tool | username | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| holehe | tool | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| amass | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| h8mail | tool | email | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| bbot | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| theharvester | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| subfinder | tool | domain | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| phoneinfoga | tool | phone | skipped | - | None | - | tool/local CLI wrapper — transport is a local binary, not an endpoint |
| cargo | re | username | verified-live | 403 | 5 | 361 | e.g. KODEGEN.ᴀɪ: Memory-efficient, Blazing-Fast, MCP tools for code generat |
| keybase | re | username | verified-live | 200 | 4 | 793 | e.g. keybase: octocat |
| pypi | re | username | verified-live | 200 | 1 | 338 | e.g. Octocat
#######

.. _description:

Octocat -- Python client for Github |
| stackoverflow | re | username | verified-live | - | 30 | 1087 | e.g. After creating pull request to &quot;octocat/Spoon-Knife&quot;, what i |
| npm | re | username | verified-live | - | 9 | 10293 | e.g. # octocat-images
[![npm version](https://badge.fury.io/js/octocat-imag |
| mempool | re | crypto_address | verified-live | 308 | 12 | 2146 | e.g. Address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa — funded 5732461664 sats, s |
| certspotter | re | domain | verified-live | 400 | 9 | 760 | e.g. example.com |
| rubygems | re | username | verified-live | 404 | 5 | 899 | e.g. Command line github |
| rapiddns | re | domain | verified-live | 200 | 3 | 1424 | e.g. example.com |
| dns_records | re | domain | verified-live | 400 | 9 | 10047 | e.g. A 172.66.147.243 (TTL 300) |
| ip_api | re | ip | verified-live | 200 | 15 | 66 | e.g. status: success |
| social | re | username | verified-live | - | 2 | 7290 | e.g. {'login': 'octocat', 'id': 583231, 'node_id': 'MDQ6VXNlcjU4MzIzMQ==',  |
| urlscan | re | domain | verified-live | 404 | 61 | 1270 | e.g. url: https://example.com/ |
| whatsmyname | scrape | username | verified-live | 302 | 1 | 587 | e.g. Username 'octocat' found on WhatsMyName results page |
| duckduckgo | scrape | domain | verified-live | - | 3 | 10100 | e.g. <!DOCTYPE html>
<html class="client-nojs vector-feature-language-in-he |
| pulsedive | api | domain | verified-live | 301 | 1 | 1821 | e.g. Indicator: example.com
Risk: none
Threats: [{'tid': 235, 'name': 'Adpo |
| ipinfo | api | ip | verified-live | 200 | 1 | 304 | e.g. IP: 8.8.8.8
City: Mountain View
Region: California
Country: US
Org: AS |
