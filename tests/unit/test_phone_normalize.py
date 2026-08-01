from src.utils.phone_normalize import lookup_id_carrier, normalize_phone_e164


def test_indonesia_local_to_e164():
    assert normalize_phone_e164("081234567890") == "+6281234567890"


def test_already_international():
    assert normalize_phone_e164("+14155552671") == "+14155552671"


def test_empty_and_short():
    assert normalize_phone_e164("") is None
    assert normalize_phone_e164("12345") is None
    assert normalize_phone_e164("1234567") is None


def test_double_zero_prefix():
    assert normalize_phone_e164("0044123456789") == "+44123456789"


def test_lookup_id_carrier_telkomsel():
    assert lookup_id_carrier("+6281234567890") == "Telkomsel"


def test_lookup_id_carrier_indosat():
    assert lookup_id_carrier("+6281450000000") == "Indosat Ooredoo"


def test_lookup_id_carrier_xl():
    assert lookup_id_carrier("+6281750000000") == "XL Axiata"


def test_lookup_id_carrier_tri():
    assert lookup_id_carrier("+6289512345678") == "Tri"


def test_lookup_id_carrier_smartfren():
    assert lookup_id_carrier("+6288112345678") == "Smartfren"


def test_lookup_id_carrier_unknown_prefix():
    assert lookup_id_carrier("+628001234567") is None


def test_lookup_id_carrier_non_indonesian():
    assert lookup_id_carrier("+14155552671") is None


def test_lookup_id_carrier_landline():
    # Jakarta landline numbers start with 21, not 8 → no mobile carrier.
    assert lookup_id_carrier("+622175012345") is None
