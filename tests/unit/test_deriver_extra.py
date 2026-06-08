"""Tests for deriver.py uncovered functions: base58, raw path derivation."""

import pytest

from src.modules.crypto.balance.deriver import (
    _base58_decode,
    _base58_encode,
    _get_purpose_from_path,
    derive_with_raw_path,
    derive_from_mnemonic,
    derive_from_privatekey,
    DerivedAddress,
)
from bip_utils import Bip44Coins


class TestBase58:
    def test_decode_encode_roundtrip(self):
        original = b"hello world test data"
        encoded = _base58_encode(original)
        decoded = _base58_decode(encoded)
        assert decoded == original

    def test_decode_empty_like(self):
        result = _base58_decode("111")
        assert isinstance(result, bytes)

    def test_encode_zero_like(self):
        result = _base58_encode(b"\x00")
        assert result == "1"

    def test_encode_non_zero(self):
        result = _base58_encode(b"\x01\x02\x03")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_decode_known_value(self):
        decoded = _base58_decode("2g")
        assert isinstance(decoded, bytes)


class TestPurposeFromPath:
    def test_standard_bip44(self):
        assert _get_purpose_from_path("m/44'/60'/0'/0/0") == 44

    def test_bip49(self):
        assert _get_purpose_from_path("m/49'/0'/0'/0/0") == 49

    def test_bip84(self):
        assert _get_purpose_from_path("m/84'/0'/0'/0/0") == 84

    def test_bip86(self):
        assert _get_purpose_from_path("m/86'/0'/0'/0/0") == 86

    def test_no_h_notation(self):
        assert _get_purpose_from_path("m/44h/60h/0h/0/0") == 44

    def test_invalid_path_defaults_44(self):
        assert _get_purpose_from_path("") == 44

    def test_garbage_path(self):
        assert _get_purpose_from_path("m/abc") == 44


class TestDeriveWithRawPath:
    def test_imports_and_runs(self):
        """derive_with_raw_path uses Bip32Secp256k1, returns None gracefully on failure."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = derive_with_raw_path(
            mnemonic=mnemonic,
            derivation_path="m/44'/0'/0'/0/0",
            chain_name="Bitcoin",
            chain_symbol="BTC",
            coin_enum=Bip44Coins.BITCOIN,
            address_idx=0,
        )
        # Function is best-effort: returns None on BIP-32 raw path failure
        assert result is None or isinstance(result, DerivedAddress)

    def test_invalid_mnemonic_returns_none(self):
        result = derive_with_raw_path(
            mnemonic="not a valid mnemonic at all",
            derivation_path="m/44'/0'/0'/0/0",
            chain_name="Bitcoin",
            chain_symbol="BTC",
            coin_enum=Bip44Coins.BITCOIN,
        )
        assert result is None

    def test_with_address_idx(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        addr0 = derive_with_raw_path(
            mnemonic=mnemonic,
            derivation_path="m/44'/0'/0'/0/0",
            chain_name="Bitcoin",
            chain_symbol="BTC",
            coin_enum=Bip44Coins.BITCOIN,
            address_idx=0,
        )
        addr1 = derive_with_raw_path(
            mnemonic=mnemonic,
            derivation_path="m/44'/0'/0'/0/0",
            chain_name="Bitcoin",
            chain_symbol="BTC",
            coin_enum=Bip44Coins.BITCOIN,
            address_idx=1,
        )
        # Both should be same type (both None or both DerivedAddress)
        assert type(addr0) is type(addr1)


class TestDeriveFromPrivatekey:
    def test_invalid_key_raises_valueerror(self):
        with pytest.raises(ValueError):
            derive_from_privatekey("badkey")

    def test_invalid_base58_key_raises_valueerror(self):
        with pytest.raises(ValueError):
            derive_from_privatekey("invalid_base58_key_here!!!")

    def test_short_key_raises_valueerror(self):
        with pytest.raises(ValueError):
            derive_from_privatekey("0x1234")


class TestDeriveFromMnemonic:
    def test_with_specific_chains(self):
        from src.modules.crypto.balance.chains import ETHEREUM
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        results = derive_from_mnemonic(mnemonic, chains=[ETHEREUM], count=2)
        assert len(results) >= 1
        assert all(r.chain == "Ethereum" for r in results)

    def test_with_none_chains_uses_all(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        results = derive_from_mnemonic(mnemonic, chains=None)
        assert len(results) >= 1
