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
  "total_sources": 98,
  "keyless_capable": 84,
  "keyless_only": 78
}
```

## Verify

```bash
uv run pytest tests/unit/test_source_registry.py \
  tests/unit/test_shodan_internetdb.py \
  tests/unit/test_etherscan_keyless.py \
  tests/unit/test_new_re_sources.py \
  tests/unit/test_breadth_re_sources.py -q
```
