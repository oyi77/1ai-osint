"""Blockchain transaction tracer and attribution engine."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from src.core.models import Finding, ScanResult, Severity
from src.modules.base.base import BaseOSINTTool
from src.modules.crypto.balance.deriver import detect_input_type

logger = logging.getLogger(__name__)

# Known entities for attribution
KNOWN_MIXERS = {
    "0x777777c9898d384f785ee44acfe945efdff5f3e0": "Tornado Cash (EVM)",
    "0xd487858c454e1529decab240cfc677f596396556": "Tornado Cash (EVM)",
    "1anwca2454556asdfg1313": "Sinbad (Bitcoin)",
    "sinbadmixeraddress": "Sinbad (Bitcoin)",
    "samouraiwhirlpool": "Samourai Whirlpool",
}

KNOWN_EXCHANGES = {
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": "Binance Deposit (EVM)",
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet (EVM)",
    "0x5015dfac77777aaaaabbbbccccdddd": "Coinbase Deposit (EVM)",
    "binancebtcaddress": "Binance Exchange (Bitcoin)",
    "coinbasebtcaddress": "Coinbase Exchange (Bitcoin)",
}


class BlockchainTxTracer(BaseOSINTTool):
    """Traces transaction history and attributes entity flows (Mixers/Exchanges/Unknown)."""

    name = "crypto_tracer"
    description = "Traces flow-of-funds across blockchains and attributes risk scores"
    version = "0.1.0"

    def __init__(self, zkit_salt: str | None = None):
        super().__init__(zkit_salt=zkit_salt)
        self.etherscan_key = os.getenv("ETHERSCAN_API_KEY", "")
        self.blockchair_key = os.getenv("BLOCKCHAIR_API_KEY", "")

    async def search(self, query: str, **kwargs) -> ScanResult:
        """Alias for scan."""
        return await self.scan(query, **kwargs)

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Scan a blockchain address, fetch transaction logs, and calculate risk scores."""
        scan_id = self._make_scan_id()
        started_at = datetime.now(timezone.utc)
        findings: list[Finding] = []

        input_type = detect_input_type(target)
        if input_type not in ("evm_address", "btc_address", "sol_address"):
            return ScanResult(
                scan_id=scan_id,
                module=self.name,
                target=target,
                status="error",
                error="Input is not a valid blockchain address (EVM, BTC, or Solana).",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        # Tracing implementation
        transactions = []
        chain = "unknown"
        if input_type == "evm_address":
            chain = "Ethereum"
            transactions = await self._trace_evm(target)
        elif input_type == "btc_address":
            chain = "Bitcoin"
            transactions = await self._trace_btc(target)
        elif input_type == "sol_address":
            chain = "Solana"
            transactions = await self._trace_solana(target)

        # Attribution / flow classification
        mix_count = 0
        exchange_count = 0
        total_tx = len(transactions)

        for tx in transactions:
            from_addr = tx.get("from", "").lower()
            to_addr = tx.get("to", "").lower()

            tx["from_entity"] = KNOWN_MIXERS.get(from_addr) or KNOWN_EXCHANGES.get(from_addr) or "Unknown Wallet"
            tx["to_entity"] = KNOWN_MIXERS.get(to_addr) or KNOWN_EXCHANGES.get(to_addr) or "Unknown Wallet"

            if from_addr in KNOWN_MIXERS or to_addr in KNOWN_MIXERS:
                mix_count += 1
            if from_addr in KNOWN_EXCHANGES or to_addr in KNOWN_EXCHANGES:
                exchange_count += 1

        if not transactions:
            # Honest no-data result: never fabricate transaction flow.
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"No Transaction Data for {target[:10]}... on {chain}",
                    description=(
                        f"Could not retrieve transaction history for {chain} address "
                        f"{target}. No API key configured or the query returned an "
                        "empty result."
                    ),
                    severity=Severity.INFO,
                    confidence=0.3,
                    tags=["crypto", "tracer", chain.lower(), "risk-info"],
                    raw_data={
                        "traced": False,
                        "address": target,
                        "chain": chain,
                        "total_transactions_traced": 0,
                        "mixer_interactions": 0,
                        "exchange_interactions": 0,
                        "risk_score": 0.1,
                        "risk_reasoning": ("No transaction data available (no API key or empty result)."),
                        "transactions": [],
                    },
                )
            )
        else:
            # Calculate risk score
            risk_score = 0.1  # base score
            reasoning = "Normal wallet activity detected."
            severity = Severity.INFO

            if mix_count > 0:
                risk_score = min(1.0, 0.7 + (mix_count * 0.1))
                reasoning = f"Direct interaction with mixer entities detected ({mix_count} times)."
                severity = Severity.CRITICAL
            elif exchange_count > 0:
                risk_score = 0.3
                reasoning = f"Direct interaction with exchange deposit/hot wallets " f"({exchange_count} times)."
                severity = Severity.MEDIUM

            # Convert to finding
            findings.append(
                Finding(
                    id=self._make_finding_id(),
                    module=self.name,
                    title=f"Transaction Flow Analysis for {target[:10]}... on {chain}",
                    description=(
                        f"Analyzed {total_tx} transactions. "
                        f"Mixer interactions: {mix_count}. Exchange interactions: "
                        f"{exchange_count}. Risk Score: {risk_score:.2f} ({reasoning})"
                    ),
                    severity=severity,
                    confidence=1.0,
                    tags=["crypto", "tracer", chain.lower(), f"risk-{severity.value}"],
                    raw_data={
                        "traced": True,
                        "address": target,
                        "chain": chain,
                        "total_transactions_traced": total_tx,
                        "mixer_interactions": mix_count,
                        "exchange_interactions": exchange_count,
                        "risk_score": risk_score,
                        "risk_reasoning": reasoning,
                        "transactions": transactions,
                    },
                )
            )

        return ScanResult(
            scan_id=scan_id,
            module=self.name,
            target=target,
            status="ok",
            findings=findings,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async def analyze(self, data: Any, **kwargs) -> dict[str, Any]:
        """Aggregate transaction attribution metrics."""
        if not isinstance(data, ScanResult):
            return {"error": "Expected ScanResult"}

        findings = data.findings
        if not findings:
            return {"risk_score": 0.1, "reason": "No findings."}

        raw = findings[0].raw_data
        return {
            "address": raw.get("address"),
            "chain": raw.get("chain"),
            "risk_score": raw.get("risk_score", 0.1),
            "reasoning": raw.get("risk_reasoning", ""),
            "mixer_interactions": raw.get("mixer_interactions", 0),
            "exchange_interactions": raw.get("exchange_interactions", 0),
        }

    async def learn(self, feedback: dict[str, Any], **kwargs) -> None:
        """No-op learning."""
        pass

    async def _trace_evm(self, address: str) -> list[dict[str, Any]]:
        """Query Etherscan for recent transactions; no key means no data."""
        if not self.etherscan_key:
            return []

        # Actual API query
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://api.etherscan.io/api",
                    params={
                        "module": "account",
                        "action": "txlist",
                        "address": address,
                        "startblock": 0,
                        "endblock": 99999999,
                        "page": 1,
                        "offset": 5,
                        "sort": "desc",
                        "apikey": self.etherscan_key,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "1":
                        return [
                            {
                                "hash": tx.get("hash"),
                                "from": tx.get("from"),
                                "to": tx.get("to"),
                                "value": tx.get("value"),
                                "timestamp": datetime.fromtimestamp(
                                    int(tx.get("timeStamp", 0)), tz=timezone.utc
                                ).isoformat(),
                            }
                            for tx in data.get("result", [])
                        ]
        except Exception as exc:
            logger.debug("Etherscan trace API error: %s", exc)

        return []

    async def _trace_btc(self, address: str) -> list[dict[str, Any]]:
        """Query Blockchair for recent Bitcoin transactions; no key means no data."""
        if not self.blockchair_key:
            return []

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://api.blockchair.com/bitcoin/dashboards/address/{address}",
                    params={"key": self.blockchair_key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Blockchair returns per-address data under data[address]["transactions"].
                    txns = (data.get("data") or {}).get(address, {}).get("transactions") or []
                    return [
                        {
                            "hash": tx.get("hash"),
                            # Blockchair dashboards do not expose per-tx from/to here,
                            # so both endpoints are the queried address.
                            "from": address,
                            "to": address,
                            "value": tx.get("output_value", 0),
                            "timestamp": datetime.fromtimestamp(int(tx.get("time", 0)), tz=timezone.utc).isoformat(),
                        }
                        for tx in txns
                    ]
        except Exception as exc:
            logger.debug("Blockchair trace API error: %s", exc)

        return []

    async def _trace_solana(self, address: str) -> list[dict[str, Any]]:
        """Query a Solana JSON-RPC endpoint for recent transactions; no RPC URL means no data."""
        rpc_url = os.getenv("SOLANA_RPC_URL", "")
        if not rpc_url:
            return []

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                sig_resp = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "getSignaturesForAddress",
                        "params": [address, {"limit": 5}],
                    },
                )
                if sig_resp.status_code != 200:
                    return []
                sigs = sig_resp.json().get("result") or []

                txs: list[dict[str, Any]] = []
                for entry in sigs:
                    sig = entry.get("signature") if isinstance(entry, dict) else entry
                    if not sig:
                        continue
                    tx_resp = await client.post(
                        rpc_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "getTransaction",
                            "params": [sig, {"maxSupportedTransactionVersion": 0}],
                        },
                    )
                    if tx_resp.status_code != 200:
                        continue
                    result = tx_resp.json().get("result")
                    if not result:
                        continue
                    message = (result.get("transaction") or {}).get("message") or {}
                    keys = message.get("accountKeys") or []
                    key_vals = [k if isinstance(k, str) else k.get("pubkey") for k in keys]
                    meta = result.get("meta") or {}
                    post = meta.get("postBalances") or []
                    pre = meta.get("preBalances") or []
                    value = 0
                    if len(post) >= 2 and len(pre) >= 2:
                        value = abs(post[1] - pre[1])
                    txs.append(
                        {
                            "hash": sig,
                            "from": key_vals[0] if key_vals else address,
                            "to": key_vals[1] if len(key_vals) > 1 else address,
                            "value": value,
                            "timestamp": datetime.fromtimestamp(
                                int(result.get("blockTime", 0)), tz=timezone.utc
                            ).isoformat(),
                        }
                    )
                return txs
        except Exception as exc:
            logger.debug("Solana trace RPC error: %s", exc)

        return []
