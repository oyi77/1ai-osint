# References

External tools, services, and collections referenced by or integrated into
1ai-osint.

## OSINT tool collections

### Cyber Detective's OSINT tools collection

- **URL**: <https://github.com/cipher387/osint_stuff_tool_collection>
- **Author**: cipher387 ([@cyb_detective](https://linktr.ee/cyb_detective))
- **Language**: HTML

Description (from the repository README):

> Hello! On my Twitter account [@cyb_detective](https://linktr.ee/cyb_detective)
> I post different services, techniques, tricks and notes about OSINT and
> more. I collect all the links from my tweets in this collection (already
> **1000+ services** for a wide variety of purposes).
>
> Thank you for following me! [@cyb_detective](https://cybdetective.com)
>
> Don't forget that OSINT's main strength is in automation. Read the
> [Netlas Cookbook](https://github.com/netlas-io/netlas-cookbook) for details
> and examples.

The repository is organized as an HTML collection and is updated almost
daily. Notable files and directories:

| Path | Purpose |
| --- | --- |
| `court_search_list.html` | Court / litigation search tools |
| `graves_search.html` | Grave / cemetery search tools |
| `hashtag_list.html` | Hashtag research tools |
| `weekly_updates/` | Weekly additions (e.g. `weekly_updates/15_january_2022.html`) |

## Integrated tools and services

The following tools and services are consumed by 1ai-osint modules (see
[Modules](modules.md) and [Configuration](configuration.md)):

### Username / people enumeration

| Tool | Use in 1ai-osint |
| --- | --- |
| [sherlock-project](https://github.com/sherlock-project/sherlock) | Core dependency powering the `people` module (people_finder / username enumeration). |
| [maigret](https://github.com/soxoj/maigret) | Optional (`pip install maigret`) — broader site coverage, slower. |

### Breach / leak data sources

| Service | API key |
| --- | --- |
| [Have I Been Pwned](https://haveibeenpwned.com/) | `HIBP_API_KEY` |
| [DeHashed](https://dehashed.com/) | `DEHASHED_API_KEY` |
| [Scylla](https://scylla.so/) | `SCYLLA_API_KEY` |
| [LeakCheck](https://leakcheck.io/) | `LEAKCHECK_API_KEY` |
| [BreachDirectory](https://breachdirectory.org/) | `BREACHDIRECTORY_API_KEY` |
| [Snusbase](https://snusbase.com/) | `SNUSBASE_API_KEY` |
| [IntelX](https://intelx.io/) | `INTELX_API_KEY` |
| [Chiasmodon](https://chiasmodon.com/) | `CHIASMODON_TOKEN` |

### Infrastructure intelligence

| Service | API key |
| --- | --- |
| [Shodan](https://www.shodan.io/) | `SHODAN_API_KEY` |
| [VirusTotal](https://www.virustotal.com/) | `VIRUSTOTAL_API_KEY` |
| [AbuseIPDB](https://www.abuseipdb.com/) | `ABUSEIPDB_API_KEY` |
| [WhoisXML API](https://www.whoisxmlapi.com/) | `WHOISXML_API_KEY` |

### AI gateway

| Service | Configuration |
| --- | --- |
| [OmniRoute](https://github.com/omniroute/omniroute) | `OMNIRoute_BASE_URL` / `OMNIRoute_API_KEY` (160+ LLMs via an OpenAI-compatible endpoint) |
| OpenAI (direct, fallback) | `OPENAI_API_KEY` / `OPENAI_BASE_URL` |

## Language and framework references

| Area | Reference |
| --- | --- |
| CLI | [Typer](https://typer.tiangolo.com/) |
| Web | [FastAPI](https://fastapi.tiangolo.com/), [uvicorn](https://www.uvicorn.org/) |
| AI orchestration | [LangGraph](https://www.langchain.com/langgraph), [langchain-openai](https://python.langchain.com/) |
| Async HTTP | [httpx](https://www.python-httpx.org/) |
| Crypto forensics | [web3.py](https://web3py.readthedocs.io/), [eth-account](https://eth-account.readthedocs.io/), [solana-py](https://docs.solanalabs.com/), [solders](https://kevinheavey.github.io/solders/), [bip-utils](https://github.com/ebellocchia/bip_utils) |
| Telegram | [Telethon](https://docs.telethon.dev/) |
| PDF generation | [reportlab](https://www.reportlab.com/) |

## Project documents

In-repo reference documents:

- `docs/INTEL_STANDARD.md` — intelligence collection standard (referenced by
  `deep-scan --profile`)
- `docs/ZKIT_PROTOCOL.md` — Zero Knowledge Identity Tracking protocol
- `docs/roadmap.md` — project master plan (see [Roadmap](roadmap.md))
- `docs/RESEARCH_PAPER.md`, `docs/PAPER.md`, `docs/RESEARCH.md` — background research
- `docs/BENCHMARK.md`, `docs/BENCHMARK_RESULTS.md` — benchmark methodology and results
- `docs/SDD.md` — software design document
- `docs/ZENODO_METADATA.md` — release metadata
