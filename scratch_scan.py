import asyncio
import logging
from src.modules.deep_scan.engine import DeepScanEngine

logging.basicConfig(level=logging.INFO)

async def main():
    print("Starting deep scan test...")
    engine = DeepScanEngine(fast=True, max_iterations=2)
    result = await engine.scan("fikri izzuddin")
    print(f"\n--- SCAN COMPLETE ---")
    print(f"Target: {result.target}")
    print(f"Identifiers found: {result.identifier_count}")
    print(f"Findings found: {result.finding_count}")
    for f in result.findings:
        print(f" - [{f.module}] {f.title}: {f.description}")
        if "verified" in f.raw_data:
            print(f"    Verified: {f.raw_data['verified']} (Conf: {f.raw_data.get('correlation_confidence')})")

if __name__ == "__main__":
    asyncio.run(main())
