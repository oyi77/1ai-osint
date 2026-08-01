# Breadth Audit — 1ai-osint vs. the OSINT field

Measured against the de-facto open-source benchmark tools, focused on the
platform's stated priority: **0-API — keyless reverse-engineered (RE)
collection before vendor APIs**.

> Method: registry inventory (`src/core/source_registry.py`, 101 sources at the
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
| username → presence | Sherlock 481, Maigret 3k+ keyless | `whatsmyname`, `social_osint`, `social_dorks_intel` (SCRAPE); `mastodon`, `reddit`, `stackoverflow`, `github`, `gitlab`, `codeberg`, `npm`, `pypi`, `rubygems`, `twitter`, `telegram`, `discord`, `keybase` (RE/SCRAPE); `sherlock`, `maigret` (TOOL) | In-process keyless breadth ~16 listed modules (600+ via `whatsmyname` scrape); Sherlock/Maigret wrappers add 481/3k+ when installed. **Gap: native keyless breadth still thin vs 481** |
| email → account | Holehe 123 keyless | `email_osint`, `gravatar_intel`, `whatsapp_check`, `telegram_check`, `hibp_free` (SCRAPE); `holehe` (TOOL) | Good; Holehe wrapper is the depth play |
| email → breach | HIBP + commercial APIs | `dehashed`, `leakcheck`, `scylla`, `snusbase`, `hibp` (API, keyed); `data_leaks`, `hibp_free` (SCRAPE); `proxynova` (RE); `h8mail` (TOOL) | Keyless breach signal now present (`proxynova` combine); depth vs HIBP still keyed |
| domain → subdomains | certspotter/rapiddns/anubis/urlscan/crt.sh/commoncrawl | `certspotter`, `rapiddns`, `anubis`, `crtsh`, `urlscan`, `wayback`, `hackertarget`, `dns_records` (RE); `dnsdumpster` (SCRAPE); `subfinder`, `amass`, `bbot` (TOOL) | **Strong — competitive keyless set** |
| domain → whois/registrant | RDAP / whois tools | `whois` (RE); `pandi_whois_intel` (SCRAPE) | Moderate; RDAP-based `whois` is keyless |
| ip → geo/ASN | ip-api.com, BGPView keyless | `ip_api`, `bgpview` (RE); `ipinfo` (API, keyless tier) | **Strong** |
| ip → ports/CVE | Shodan InternetDB keyless | `nmap`, `httpx` (TOOL); `shodan` (API, InternetDB fallback, keyless); `vuln_scanner` (RE) | Strong; InternetDB gives keyless ports/CVEs |
| org → domains | theHarvester, Censys/SecurityTrails API | `theharvester` (TOOL); `domain_recon`, `google_dork_intel` (SCRAPE); `securitytrails`, `censys` (API keyed) | Moderate; keyless org→domain is SCRAPE-based |
| phone | PhoneInfoga keyless | `phone_finder` (SCRAPE); `veriphone` (RE); `phoneinfoga` (TOOL) | Improved — keyless carrier/line-type now RE; PhoneInfoga wrapper remains the depth play |
| crypto | blockchair/mempool keyless | `blockchair`, `mempool` (RE); `etherscan` (API, keyless fallback); `crypto_balance`, `crypto_tracer` (RE); `cargo` (RE) | **Strong** |
| image | exiftool, EXIF data | `exiftool` (TOOL); `google_dork_intel`, `wayback_intel` (SCRAPE) | Moderate |
| darknet / paste | paste sites, darkweb crawlers | `paste`, `darknet`, `bts_intel` (SCRAPE) | Moderate |
| threat feeds | URLhaus, ThreatFox, MalwareBazaar keyless | `urlhaus`, `threatfox`, `feodo`, `malwarebazaar` (RE); `otx`, `pulsedive` (API, keyless tier); `abuseipdb`, `virustotal`, `greynoise` (API keyed) | **Strong — keyless feeds on RE** |
| entity extraction | AI/NER pipelines | LangGraph orchestrator + entity extraction, correlation, risk scoring (LOCAL) | Strong (local, keyless) |

## 0-API posture (measured)

```json
{"total_sources": 101, "keyless_capable": 87, "keyless_only": 81}
```

- 87/101 sources run with zero API keys; 81 are keyless by construction.
- New in this audit: `bgpview`, `certspotter`, `rapiddns`, `anubis`, `urlscan`
  — all keyless RE subdomain/ASN sources.
- P1-gap closures: `proxynova` (keyless breach/paste combine), `veriphone`
  (keyless phone carrier/line-type), `keybase` (keyless username profile).

## P1 gaps — status

1. **Keyless breach corpus** — *addressed*: `proxynova` combine gives keyless
   `domain | line` breach/paste signal by email/username/phone/IP. Residual:
   corpus depth still keyed (`dehashed`/`leakcheck`/`scylla`/`snusbase`/`hibp`).
2. **Phone RE** — *addressed*: `veriphone` provides keyless carrier/line-type
   lookup; `phone_finder` (SCRAPE) and `phoneinfoga` (TOOL) remain.
3. **Username breadth** — *improved*: `keybase` adds a profile RE source
   (~16 listed modules now). Residual: still far below Sherlock's 481 /
   Maigret's 3k+; wrappers exist, native RE set should keep growing.

## Honest verdict

Measurable strengths: the keyless subdomain set (7 RE sources + 2 tools) and
crypto/threat-feed coverage match or beat open-source baselines while running
with zero keys. Structural gaps remain — breach corpus depth (keyed APIs still
out-depth the keyless combine) and username breadth (~16 native modules vs
Sherlock's 481) — which no single-tool comparison can close without either
more keyless endpoints or vendor keys. "Best in the world" is not claimed
here; this is the measured baseline that subsequent phases improve against.
