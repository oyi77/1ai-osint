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
  "total_sources": 88,
  "keyless_capable": 74,
  "keyless_only": 68
}
```

## Verify

```bash
uv run pytest tests/unit/test_source_registry.py \
  tests/unit/test_shodan_internetdb.py \
  tests/unit/test_etherscan_keyless.py -q
```
