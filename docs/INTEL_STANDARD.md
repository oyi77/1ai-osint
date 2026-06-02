# Intelligence Standard — Agency-Aligned OSINT Packet (v1)

Target fidelity: structured like **CIA PDB / FBI Guardian / BIN tactical brief** sections,
sourced only from **lawful open sources + licensed breach APIs** configured by the operator.

## Classification banner

Every export MUST include:

`UNCLASSIFIED // OPEN SOURCE INTELLIGENCE // LAWFUL USE ONLY`

## Mandatory sections (HTML + JSON `briefing`)

| § | Section | Agency analogue | Minimum content |
|---|---------|-----------------|-----------------|
| 0 | BLUF | PDB lead | 1 paragraph: who, exposure, risk, top 3 facts |
| I | Key judgments | Analyst notes | 3–7 bullet analytic conclusions with confidence |
| II | Subject identification | Identity resolution | Name, aliases, handles, emails, phones, NIK/ID, locations |
| III | Digital presence | DNI social matrix | Platform, handle, URL, status, confidence, collector |
| IV | Breach & credential intel | CTI credential exposure | Per-breach field rows (email, hash, phone, DOB, address…) |
| V | Threat & exposure | Risk assessment | Rules triggered + overall level |
| VI | Link analysis | Association chart | Identity graph (ZKIT) |
| VII | Chronology | Timeline | UTC-ordered events |
| VIII | Intelligence gaps | Collection requirements | Explicit unknowns |
| IX | Recommended collection | Tasking | Prioritized pivots + modules |
| A | Evidence register | Source trace | Value, type, source, reliability, confidence |
| B | Warnings | Caveats | Low confidence, legal, incomplete collection |

## Field taxonomy (breach / PII)

Normalized keys for Section IV (map any source into these):

- **Identity:** `full_name`, `aliases`, `username`, `gender`, `date_of_birth`, `nik`, `passport_number`
- **Contact:** `email`, `phone`, `address`, `city`, `region`, `country`
- **Digital:** `ip_address`, `domain`, `facebook_id`, `telegram_id`
- **Credential:** `password`, `password_hash`, `salt`, `breach_name`, `breach_date`, `data_classes`
- **Professional:** `job_title`, `company_name`, `registration_date`, `last_activity`
- **Financial:** `crypto_address` (when applicable)

## Source reliability (NATO Admiralty)

| Grade | Meaning |
|-------|---------|
| A | Official / verified API (e.g. GitHub API 200) |
| B | Established platform registry |
| C | Social presence / breach aggregator |
| D | Scraped / secondary index |
| F | Unverified single source |

## Collection profiles (`deep-scan --profile`)

| Profile | Time budget | Modules | Iterations | Use case |
|---------|-------------|---------|------------|----------|
| `fast` | ~1–10 min | Social + people + keyed breaches | 2 | Triage |
| `standard` | ~10–30 min | + email, phone, data_leaks | 3 | Routine case |
| `deep` | ~30–90 min | + domain, gitleaks (domain) | 5 | Full OSINT |
| `agency` | ~60–180 min | All keyed sources + max pivots | 8 | Near agency packet |

## Definition of done (per target)

- [ ] BLUF references only facts present in evidence register
- [ ] Every handle in §III has URL or explicit “unavailable”
- [ ] §IV lists each breach source OR §VIII explains missing API keys
- [ ] §VIII never empty on first run (at minimum: “configure HIBP/DeHashed…”)
- [ ] JSON includes `briefing` + `source_blocks` + `schema_version`

## Legal

Operators are responsible for authorization, local law, and data protection.
This tool does not access classified systems.
