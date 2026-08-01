# Breadth Audit — 1ai-osint vs. the OSINT field

Measured against the de-facto open-source benchmark tools, focused on the
platform's stated priority: **0-API — keyless reverse-engineered (RE)
collection before vendor APIs**.

> Method: registry inventory (`src/core/source_registry.py`, 98 sources at the
> time of this audit), per-source transport classification (RE / SCRAPE /
> API / TOOL / LOCAL). Tool wrappers count as *available* but only effective
> when the CLI binary is installed. No claim of live-verified network results
> here — each source's tests run against mocked HTTP; live reachability is a
> soak/CI concern, not asserted in this matrix.

## Competitor baselines

| Tool | Scope | Keyless? |
|---|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | 481 username→profile sites | yes |
| [Maigret](https://github.com/soxoj/maigret) | 3,000+ username→profile sites | yes |
| [Holehe](https://github.com/megadose/holehe) | 123 email→account services | yes |
| [theHarvester](https://github.com/laramies/theHarvester) | emails, hosts, subdomains, org data | mostly (API feeds optional) |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | ~230 scan modules | mixed |
| Subdomain RE set | certspotter, rapiddns, anubis, urlscan.io, crt.sh, bufferover, commoncrawl | yes |
| BGPView | IP→ASN/prefix/registry (keyless) | yes |
| PhoneInfoga | phone→carrier/formatting lookup | yes |

## Coverage matrix

Each cell: transport kind used by 1ai-osint for that category
(RE / SCRAPE / API / TOOL / **absent**).

| Category | Competitor best | 1ai-osint | Verdict |
|---|---|---|---|
| username → presence | Sherlock 481, Maigret 3k+ keyless | `whatsmyname`, `social_osint`, `social_dorks_intel` (SCRAPE); `mastodon`, `reddit`, `stackoverflow`, `github`, `gitlab`, `codeberg`, `npm`, `pypi`, `rubygems`, `twitter`, `telegram`, `discord` (RE/SCRAPE); `sherlock`, `maigret` (TOOL) | In-process keyless breadth ~15 sites; Sherlock/Maigret wrappers add 481/3k+ when installed. **Gap: native keyless breadth is thin** |
| email → account | Holehe 123 keyless | `email_osint`, `gravatar_intel`, `whatsapp_check`, `telegram_check`, `hibp_free` (SCRAPE); `holehe` (TOOL) | Good; Holehe wrapper is the depth play |
| email → breach | HIBP + commercial APIs | `dehashed`, `leakcheck`, `scylla`, `snusbase`, `hibp` (API, keyed); `data_leaks`, `hibp_free` (SCRAPE); `h8mail` (TOOL) | **P1 gap: breach corpus is keyed-only in-process; keyless breach signal is thin** |
| domain → subdomains | certspotter/rapiddns/anubis/urlscan/crt.sh/commoncrawl | `certspotter`, `rapiddns`, `anubis`, `crtsh`, `urlscan`, `wayback`, `hackertarget`, `dns_records` (RE); `dnsdumpster` (SCRAPE); `subfinder`, `amass`, `bbot` (TOOL) | **Strong — competitive keyless set** |
| domain → whois/registrant | RDAP / whois tools | `whois` (RE); `pandi_whois_intel` (SCRAPE) | Moderate; RDAP-based `whois` is keyless |
| ip → geo/ASN | ip-api.com, BGPView keyless | `ip_api`, `bgpview` (RE); `ipinfo` (API, keyless tier) | **Strong** |
| ip → ports/CVE | Shodan InternetDB keyless | `nmap`, `httpx` (TOOL); `shodan` (API, InternetDB fallback, keyless); `vuln_scanner` (RE) | Strong; InternetDB gives keyless ports/CVEs |
| org → domains | theHarvester, Censys/SecurityTrails API | `theharvester` (TOOL); `domain_recon`, `google_dork_intel` (SCRAPE); `securitytrails`, `censys` (API keyed) | Moderate; keyless org→domain is SCRAPE-based |
| phone | PhoneInfoga keyless | `phone_finder` (SCRAPE); `phoneinfoga` (TOOL) | **P1 gap: keyless phone RE is thin** |
| crypto | blockchair/mempool keyless | `blockchair`, `mempool` (RE); `etherscan` (API, keyless fallback); `crypto_balance`, `crypto_tracer` (RE); `cargo` (RE) | **Strong** |
| image | exiftool, EXIF data | `exiftool` (TOOL); `google_dork_intel`, `wayback_intel` (SCRAPE) | Moderate |
| darknet / paste | paste sites, darkweb crawlers | `paste`, `darknet`, `bts_intel` (SCRAPE) | Moderate |
| threat feeds | URLhaus, ThreatFox, MalwareBazaar keyless | `urlhaus`, `threatfox`, `feodo`, `malwarebazaar` (RE); `otx`, `pulsedive` (API, keyless tier); `abuseipdb`, `virustotal`, `greynoise` (API keyed) | **Strong — keyless feeds on RE** |
| entity extraction | AI/NER pipelines | LangGraph orchestrator + entity extraction, correlation, risk scoring (LOCAL) | Strong (local, keyless) |

## 0-API posture (measured)

```json
{"total_sources": 98, "keyless_capable": 84, "keyless_only": 78}
```

- 84/98 sources run with zero API keys; 78 are keyless by construction.
- New in this audit: `bgpview`, `certspotter`, `rapiddns`, `anubis`, `urlscan`
  — all keyless RE subdomain/ASN sources.

## P1 gaps (next work)

1. **Keyless breach corpus** — `dehashed`/`leakcheck`/`scylla`/`snusbase`/`hibp`
   are keyed. Keyless alternatives are scrape-only (`data_leaks`, `hibp_free`).
2. **Phone RE** — only `phone_finder` (SCRAPE) in-process; no keyless carrier
   lookup source.
3. **Username breadth** — in-process keyless presence checks ~15 sites vs.
   Sherlock's 481 / Maigret's 3k+. Wrappers exist but the native RE set should
   grow (e.g. keyless profile endpoints beyond the current major platforms).

## Honest verdict

Measurable strengths: the keyless subdomain set (7 RE sources + 2 tools) and
crypto/threat-feed coverage match or beat open-source baselines while running
with zero keys. Structural gaps remain — breach corpus depth, phone, and
username breadth — which no single-tool comparison can close without either
more keyless endpoints or vendor keys. "Best in the world" is not claimed
here; this is the measured baseline that subsequent phases improve against.
