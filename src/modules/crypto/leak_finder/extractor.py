"""Key extraction engine for raw text."""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)
from src.modules.crypto.balance.deriver import _base58_decode, _base58_encode

class KeyType(str, Enum):
    HEX_PRIVATE_KEY = "hex_private_key"
    BASE58_SOLANA = "base58_solana"
    WIF = "wif"
    MNEMONIC = "mnemonic"

@dataclass
class ExtractedKey:
    key_raw: str
    key_type: KeyType
    key_hex: Optional[str] = None
    derived_addresses: dict[str, str] = field(default_factory=dict)

_HEX_KEY_PATTERN = re.compile(r"(?:0x)?(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
_WIF_PATTERN = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?![1-9A-HJ-NP-Za-km-z])")
_BASE58_SOLANA_PATTERN = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([2-9A-HJ-NP-Za-km-z][1-9A-HJ-NP-Za-km-z]{85,87})(?![1-9A-HJ-NP-Za-km-z])")
_KEY_CONTEXT_PATTERN = re.compile(r"(?i)(private[_\s-]*key|secret[_\s-]*key|priv[_\s-]*key|privkey|priv_key|pvk|signing[_\s-]*key|seed|hex)")
_CONTEXTUAL_HEX_KEY_RE = re.compile(
    r"(?:private[_\s-]*key|secret[_\s-]*key|priv[_\s-]*key|privkey|priv_key|"
    r"pvk|signing[_\s-]*key|wallet[_\s-]*key|bot[_\s-]*key|deployer[_\s-]*key|"
    r"owner[_\s-]*key|admin[_\s-]*key|funder[_\s-]*key)[\s:=]*[\"']?(?:0x)?([0-9a-fA-F]{64})", re.IGNORECASE)

# JSON-style: "private_key": "0x..." or "secret": "0x..."
_JSON_KEY_RE = re.compile(
    r'"(?:private[_-]?key|secret[_-]?key|priv[_-]?key|wallet[_-]?key|mnemonic|seed)"\s*:\s*"([^"]+)"', re.IGNORECASE)

# Env-style: PRIVATE_KEY=0x... or MNEMONIC="word word ..."
_ENV_KEY_RE = re.compile(
    r'^(?:PRIVATE[_-]?KEY|SECRET[_-]?KEY|WALLET[_-]?KEY|MNEMONIC|SEED[_-]?PHRASE)=(?:["\'])?([^\s"\'#\n]+)', re.IGNORECASE | re.MULTILINE)
_MNEMONIC_WORD_RE = re.compile(r"[a-z]{3,8}")
_BIP39_WORDS: Optional[set[str]] = None

def _load_bip39_words() -> set[str]:
    global _BIP39_WORDS
    if _BIP39_WORDS is not None:
        return _BIP39_WORDS
    try:
        from bip_utils import Bip39WordsFinder
        _BIP39_WORDS = set(Bip39WordsFinder("english").GetAllWords())
    except Exception:
        _BIP39_WORDS = set()
    return _BIP39_WORDS

def _derive_evm_address(hex_key: str) -> Optional[str]:
    try:
        from eth_account import Account
        return Account.from_key(bytes.fromhex(hex_key)).address
    except Exception:
        return None

def _derive_solana_address(hex_key: str) -> Optional[str]:
    try:
        from solders.keypair import Keypair
        return str(Keypair.from_seed(bytes.fromhex(hex_key)[:32]).pubkey())
    except Exception:
        return None

def _derive_solana_address_from_base58(b58_key: str) -> Optional[str]:
    try:
        from solders.keypair import Keypair
        decoded = _base58_decode(b58_key)
        if len(decoded) == 64:
            kp = Keypair.from_bytes(decoded)
            return str(kp.pubkey())
        elif len(decoded) == 32:
            kp = Keypair.from_seed(decoded)
            return str(kp.pubkey())
        return None
    except Exception:
        return None

def _derive_btc_address_wif(wif: str) -> Optional[str]:
    try:
        from bip_utils import WifDecoder, P2PKHAddrEncoder
        priv_key_bytes, _ = WifDecoder.Decode(wif)
        return P2PKHAddrEncoder.EncodeKey(priv_key_bytes)
    except Exception:
        return None

def _derive_mnemonic_addresses(mnemonic: str) -> dict[str, str]:
    try:
        from src.modules.crypto.balance.deriver import derive_from_mnemonic
        return {d.chain: d.address for d in derive_from_mnemonic(mnemonic, count=1)}
    except Exception:
        return {}

def _validate_mnemonic(mnemonic: str) -> bool:
    try:
        from bip_utils import Bip39MnemonicValidator
        return Bip39MnemonicValidator().IsValid(mnemonic.strip())
    except Exception:
        return False

def extract_keys(text: str) -> list[ExtractedKey]:
    results: list[ExtractedKey] = []
    seen: set[str] = set()

    # 1. Contextual hex keys
    for key_hex, _ in _find_contextual_hex_keys(text):
        norm = key_hex.lower()
        if norm in seen:
            continue
        seen.add(norm)
        addrs: dict[str, str] = {}
        evm = _derive_evm_address(norm)
        if evm:
            addrs["Ethereum"] = addrs["BSC"] = addrs["Polygon"] = evm
        sol = _derive_solana_address(norm)
        if sol:
            addrs["Solana"] = sol
        if addrs:
            results.append(ExtractedKey(key_raw=key_hex, key_type=KeyType.HEX_PRIVATE_KEY, key_hex=norm, derived_addresses=addrs))

    # 1b. JSON-style key-value pairs
    for m in _JSON_KEY_RE.finditer(text):
        val = m.group(1).strip()
        # Check if it's a hex key
        hex_match = re.match(r"(?:0x)?([0-9a-fA-F]{64})", val)
        if hex_match:
            k = hex_match.group(1).lower()
            if k not in seen:
                seen.add(k)
                addrs: dict[str, str] = {}
                evm = _derive_evm_address(k)
                if evm:
                    addrs["Ethereum"] = addrs["BSC"] = addrs["Polygon"] = evm
                sol = _derive_solana_address(k)
                if sol:
                    addrs["Solana"] = sol
                if addrs:
                    results.append(ExtractedKey(key_raw=val, key_type=KeyType.HEX_PRIVATE_KEY, key_hex=k, derived_addresses=addrs))

    # 1c. Env-style key=value
    for m in _ENV_KEY_RE.finditer(text):
        val = m.group(1).strip()
        hex_match = re.match(r"(?:0x)?([0-9a-fA-F]{64})", val)
        if hex_match:
            k = hex_match.group(1).lower()
            if k not in seen:
                seen.add(k)
                addrs: dict[str, str] = {}
                evm = _derive_evm_address(k)
                if evm:
                    addrs["Ethereum"] = addrs["BSC"] = addrs["Polygon"] = evm
                sol = _derive_solana_address(k)
                if sol:
                    addrs["Solana"] = sol
                if addrs:
                    results.append(ExtractedKey(key_raw=val, key_type=KeyType.HEX_PRIVATE_KEY, key_hex=k, derived_addresses=addrs))

    # 2. Standalone hex with context
    for m in _HEX_KEY_PATTERN.finditer(text):
        k = m.group(1).lower()
        if k in seen:
            continue
        start = max(0, m.start() - 60)
        if not (m.group(0).startswith("0x") or bool(_KEY_CONTEXT_PATTERN.search(text[start:m.start()]))):
            continue
        seen.add(k)
        addrs: dict[str, str] = {}
        evm = _derive_evm_address(k)
        if evm:
            addrs["Ethereum"] = addrs["BSC"] = addrs["Polygon"] = evm
        sol = _derive_solana_address(k)
        if sol:
            addrs["Solana"] = sol
        if addrs:
            results.append(ExtractedKey(key_raw=m.group(1), key_type=KeyType.HEX_PRIVATE_KEY, key_hex=k, derived_addresses=addrs))

    # 3. WIF keys
    for m in _WIF_PATTERN.finditer(text):
        wif = m.group(1)
        if wif in seen:
            continue
        seen.add(wif)
        btc = _derive_btc_address_wif(wif)
        if btc:
            results.append(ExtractedKey(key_raw=wif, key_type=KeyType.WIF, derived_addresses={"Bitcoin": btc}))

    # 4. Base58 Solana keys
    for m in _BASE58_SOLANA_PATTERN.finditer(text):
        b58 = m.group(1)
        if len(b58) not in (87, 88) or b58 in seen:
            continue
        seen.add(b58)
        sol = _derive_solana_address_from_base58(b58)
        if sol:
            decoded = _base58_decode(b58)
            results.append(ExtractedKey(key_raw=b58, key_type=KeyType.BASE58_SOLANA, key_hex=decoded.hex() if len(decoded) == 64 else None, derived_addresses={"Solana": sol}))

    # 5. BIP-39 mnemonics
    bip39 = _load_bip39_words()
    if bip39:
        words = _MNEMONIC_WORD_RE.findall(text.lower())
        for length in (12, 15, 18, 21, 24):
            for i in range(len(words) - length + 1):
                cands = words[i:i + length]
                if not all(w in bip39 for w in cands):
                    continue
                candidate = " ".join(cands)
                if candidate in seen:
                    continue
                if _validate_mnemonic(candidate):
                    seen.add(candidate)
                    results.append(ExtractedKey(key_raw=candidate, key_type=KeyType.MNEMONIC, derived_addresses=_derive_mnemonic_addresses(candidate)))

    return results

def _find_contextual_hex_keys(text: str) -> list[tuple[str, int]]:
    return [(m.group(1), m.start(1)) for m in _CONTEXTUAL_HEX_KEY_RE.finditer(text)]
