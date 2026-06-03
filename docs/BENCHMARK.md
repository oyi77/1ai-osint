# 1ai-osint: Scanner Throughput Benchmarking & Reproducibility

This document details instructions for running and reproducing the performance benchmark for the ZKIT crypto balance scanner.

## Benchmark Design

The throughput benchmark runs the `RandomScanner` engine for a set duration, checking generated BIP-39 mnemonic phrases against EVM (Ethereum, BSC, Polygon), Solana, and Bitcoin blockchains using public JSON-RPC nodes.

Performance is judged on three metrics:
1. **Throughput (Mnemonics/sec)**: Target >= 20.0 mnemonics/sec.
2. **Addresses/sec**: Derived addresses validated per second across all chains.
3. **API Error Rate**: Percentage of RPC requests returning HTTP/RPC errors. Target <= 10.0%.

## Running the Benchmark

Execute the benchmark utility script:

```bash
python scripts/benchmark.py --duration 60 --workers 20
```

### Options

* `--duration <seconds>`: Duration of the benchmark (default: 60).
* `--workers <count>`: Number of concurrent async workers checking balances (default: 20).

## Reproducibility Package

To verify reproducibility:

1. Clean python cache:
   ```bash
   find . -type d -name "__pycache__" -exec rm -rf {} +
   ```
2. Start the benchmark in a clean environment:
   ```bash
   python scripts/benchmark.py --duration 30 --workers 25
   ```
3. The benchmark will output verification checks (PASS/FAIL) on overall execution throughput.
