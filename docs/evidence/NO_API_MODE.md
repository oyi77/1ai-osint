# NO_API — 0-API Mode

The platform pursues a **0-API priority**: collection must work with zero API
keys by default, leaning on reverse-engineered (RE) public endpoints and local
tooling, with vendor APIs treated as optional amplification.

## Enabling

- Env var: `NO_API=1`
- CLI: `--no-api` on `deep-scan` and `zkit-deep-scan`

## What changes in 0-API mode

`DeepScanEngine._get_active_modules`:

1. Filters the module list to sources that can run **keyless**
   (`source_registry.can_run_keyless`).
2. Sorts the survivors by transport priority — RE first:

   ```
   RE (0) < SCRAPE (1) < keyless API (2) < keyed API (3) < TOOL (4) < LOCAL (5)
   ```

Keyed-only sources are skipped entirely; nothing in 0-API mode waits on or
fails over to an absent key.

## Excluded in 0-API mode (key required)

`dehashed`, `leakcheck`, `snylla`, `snusbase`, `hibp`, `intelx`, `abuseipdb`,
`censys`, `securitytrails`, `virustotal`, `greynoise`, `hunter`, `wigle`,
`zoomeye`.

## Keyless RE-first sources (no key, no account)

Reverse-engineered public endpoints, transport priority RE (0):

- **hackertarget** — domain → `hostsearch` CSV (`host,ip` leaks), IP →
  `reverseiplookup`; skips `error`/`api count exceeded` lines; never raises.
- **dns_records** — Google DoH (`dns.google/resolve`) over
  A/AAAA/NS/MX/TXT/CNAME; labeled leaks (`A 93.184.216.34 (TTL 300)`).
- **mempool** — `mempool.space` address summary + top txs (funded/spent sats,
  confirmed txs, UTXO and unconfirmed counts, top-10 tx values).
- **ip_api** — `ip-api.com` (HTTP) with `fields` param; 15-field geolocation
  leaks incl. proxy/ASN flags on `status: success`.
- **pgp_keys** — `keys.openpgp.org` by-email SHA-1 digest lookup; emits a leak
  only when a `-----BEGIN PGP PUBLIC KEY BLOCK-----` block is returned.
- **certspotter** — `certspotter.com/api/v0/certs` by domain (include
  subdomains, expanded DNS names); lowercased, trailing-dot-stripped names.
- **rapiddns** — `rapiddns.io/subdomain` HTML table by domain; keyless.
- **anubis** — `jldc.me/anubis/subdomains` JSON subdomain index; keyless.
- **urlscan** — `urlscan.io/api/v1/search` by `domain:` query; url/ip/asn
  leaks, deduplicated; keyless public tier.
- **bgpview** — `api.bgpview.io/ip/{ip}` ASN/prefix/RIR/country leaks;
  IPv4/IPv6 only, skips non-IP input.
- **proxynova** — `api.proxynova.com/combine` by email/username/phone/IP;
  deduped `domain | line` breach/paste leaks; keyless.
- **veriphone** — `api.veriphone.io/v2/verify` by phone; carrier/line
  type/country/format leaks on `status: success` + `phone_valid`; keyless.
- **keybase** — `keybase.io` user lookup by username; full name/bio/location/
  site/avatar leaks; keyless.
- **huggingface** — `huggingface.co/{u}` profile lookup; HTTP 200/404
  discriminates presence; leaks `huggingface: <u>` + `full name: X`; keyless.
- **scratch** — `scratch.mit.edu/users/{u}/` presence leak; keyless.
- **itchio** — `itch.io/profile/{u}`; leaks `itchio: <u>` + `profile title: X`;
  keyless.
- **codeforces** — `codeforces.com/api/user.info?handles={u}` JSON
  (`status: OK`); leaks rating/rank/max-rating/registration date; keyless.
- **devto** — `dev.to/{u}` profile page (JSON-LD `sameAs`); leaks
  `devto: <u>`, profile title, description, joined date, social links; keyless.
- **steam** — `steamcommunity.com/id/{u}/?xml=1` XML feed; leaks steam ID,
  display name, steam64 ID, member-since, real name, location, summary;
  unknown users also return 200 — an `<error>` body is treated as a miss;
  keyless.
- **chess** — `chess.com/member/{u}` profile page; title, full name,
  location, joined leaks; ToS restricts automated scraping — rate-limited
  (`request_delay`), public profile page only; keyless.
- **letterboxd** — `letterboxd.com/{u}/` profile page; profile title,
  description, external links, member-since leaks; 404 = miss; keyless.
- **medium** — `{u}.medium.com/` profile subdomain (the `@username` path is
  Cloudflare-challenged for non-browser clients); title/description leaks;
  soft-404 and CF challenges treated as misses; keyless.
- **pastebin** — `pastebin.com/u/{u}` user page; profile name + latest paste
  dates; **case-preserving** (no lowercase of input); ToS restricts automated
  scraping — rate-limited; keyless.
- **youtube** — `youtube.com/@{u}/about?hl=en&gl=US` channel about page
  (follows the 303 canonical redirect); title, description, join date, country
  leaks; keyless.
- **fandom** — `community.fandom.com/api.php` MediaWiki `action=query`
  list=users JSON; user id, registration, edit count, groups, gender leaks;
  `missing` entry = miss; keyless.
- **whatsmyname** — keyless username presence-echo scrape (SCRAPE transport,
  not RE): queries the search page and echoes the query, so it hits almost
  always — weak signal by design; wired into deep scan as an in-process
  username source.

### P4: 30 keyless sources wired into the deep scan engine

`src/modules/deep_scan/_module_config.py` now wires in all keyless sources
(`MODULE_INPUTS` 52→92, `SOURCE_MODULES` 31→69), matching the registry's
keyless set so 0-API mode and normal mode activate the same RE-first breadth:

- RE/SCRAPE (keyless): threatfox, feodo, malwarebazaar, blockchair, cargo,
  npm, pypi, rubygems, mastodon, reddit, stackoverflow, codeberg, social,
  s3, rss, twitter, telegram, paste, duckduckgo, discord, darknet,
  dnsdumpster, huggingface, scratch, itchio, codeforces, devto, steam,
  chess, letterboxd, medium, pastebin, youtube, fandom.
- Keyless API: etherscan, ipinfo, pulsedive, github.
- Free-intel additions (in-process dispatch, not source modules):
  pandi_whois_intel, data_go_id_intel.

0-API mode now activates **86 modules** (`DeepScanEngine(no_api=True)
._get_active_modules()`), ordered RE → SCRAPE → keyless API → keyed API →
TOOL → LOCAL.

## Keyless TOOL adapters (require local CLI)

Eleven external-tool wrappers are wired into the deep scan engine through the
`source_adapter` path. They are keyless (no API key) but require the CLI
binary on `PATH`; when the CLI is absent the source returns an audited empty
result instead of raising.

- **sherlock / maigret** — username presence across 481 / 3k+ sites
  (`--print-found --json`).
- **holehe** — email→account registration check.
- **theharvester** — org/domain→emails/subdomains/hosts.
- **subfinder / amass / bbot** — subdomain enumeration.
- **nmap** — host discovery / port scan (IP or domain).
- **httpx** — HTTP probing of domain/IP/URL targets.
- **phoneinfoga** — phone number recon (scan/format/validate).
- **h8mail** — email breach/leak lookup.

Each is ordered after RE/SCRAPE sources in 0-API mode (transport priority 4).

## Keyless-capable API sources

- **Shodan** — falls back to the keyless [Shodan InternetDB](
  https://internetdb.shodan.io) endpoint when no `SHODAN_API_KEY` is set
  (IPv4 only; ports/hostnames/CPEs/vulns/tags; returns nothing on domains or
  non-IPv4 input; never raises).
- **Etherscan** — keyless public endpoint (~5 req/s); `ETHERSCAN_API_KEY` is
  attached only when configured.
- **OTX / ipinfo / pulsedive / GitHub** — keyless tiers or key-optional.

## Measuring the posture

`scripts/live_benchmark.py --json` now embeds a `transports` dimension in its
receipt, from `source_registry.no_api_metrics()`:

```json
"transports": {
  "total_sources": 113,
  "keyless_capable": 99,
  "keyless_only": 93
}
```

## Verify

```bash
uv run pytest tests/unit/test_source_registry.py \
  tests/unit/test_shodan_internetdb.py \
  tests/unit/test_etherscan_keyless.py \
  tests/unit/test_new_re_sources.py \
  tests/unit/test_breadth_re_sources.py \
  tests/unit/test_p1_gap_sources.py \
  tests/unit/test_username_re_sources.py -q
```
