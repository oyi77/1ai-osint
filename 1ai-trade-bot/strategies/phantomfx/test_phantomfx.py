#!/usr/bin/env python3
"""
PhantomFX Integration Test
Tests the PhantomFX Connector with sample outputs.

Usage:
    python3 test_phantomfx.py
    python3 test_phantomfx.py --with-mt5  # Also test MT5 connection
"""

import json
import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from phantomfx_connector import (
    parse_phantomfx_output,
    extract_telegram_signal,
    extract_killzone_broadcast,
    extract_circuit_alert,
    process_output,
    send_telegram,
)


SAMPLE_BUY_SIGNAL = """
```json
{
 "system": "PhantomFX | GENESIS AI Trader v4.0",
 "cycle_id": "phantomfx_20260603T013500",
 "session": "London",
 "killzone_active": true,
 "circuit_breaker": false,
 "loss_count_today": 1,
 "combat_style": "SNIPER",
 "style_reason": "Market normal dengan struktur H1 jelas, setup A-grade teridentifikasi",
 "reflection": "Trade sebelumnya SL hit karena entry di Asian session. Pelajaran: tunggu London open.",
 "symbol": "XAUUSD",
 "strategy": "SMC H1 sweep + M5 CHoCH buy setup dari H1 bullish OB",
 "skc_score": {"s_struktur": 3.5, "k_konfluensi": 3.0, "c_konteks": 2.0, "total": 8.5, "zone": "YELLOW"},
 "confluences": ["Liquidity sweep M15", "H1 bullish OB", "London session overlap"],
 "layer_1_status": "TRIGGERED",
 "layer_2_status": "CONFIRMED",
 "action": "BUY",
 "entry": 2650.50,
 "sl": 2642.00,
 "tp": 2670.00,
 "sl_pips": 85,
 "tp_pips": 195,
 "rr_ratio": "1:2.29",
 "rr_valid": true,
 "risk_tier": "0.5%",
 "risk_zone": "YELLOW",
 "confidence": 0.78,
 "grade": "B",
 "htf_sl_level": "H1 invalidation below 2640 (H1 structure break)",
 "reasoning": "XAUUSD menunjukkan bullish momentum di H1 setelah liquidity sweep di M15. H1 OB di 2645-2650 menjadi zona entry. DXY melemah mendukung kenaikan emas. London session aktif memberikan volatilitas optimal. R:R 1:2.29 valid. SL ditempatkan di bawah H1 structure untuk memberi ruang bernapas.",
 "mt5_webhook": {
   "ready": true,
   "symbol": "XAUUSD",
   "type": "OP_BUY",
   "price": 2650.50,
   "sl": 2642.00,
   "tp": 2670.00,
   "risk_percent": 0.5,
   "comment": "PhantomFX_SNIPER_B_20260603T013500"
 },
 "notify_telegram": true
}
```

---TELEGRAM_SIGNAL_START---
⚡ *PhantomFX Signal Alert*
🤖 GENESIS AI Trader v4\\.0 \\| Institutional Grade

━━━━━━━━━━━━━━━━━━━━━━━━━━
🎖️ *COMBAT STYLE: SNIPER*
📍 _Market normal, struktur H1 jelas_

━━━━━━━━━━━━━━━━━━━━━━━━━━
🔬 *SKC SCORE: 8\\.5/10* → 🟡 YELLOW

┌ S \\(Struktur\\): 3\\.5/4\\.0
├ K \\(Konfluensi\\): 3\\.0/3\\.5
└ C \\(Konteks\\): 2\\.0/2\\.5

━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 *SINYAL TRADING*

🔸 Pair : *XAUUSD*
🔸 Aksi : *🟢 BUY*
🔸 Strategi : SMC H1 sweep \\+ M5 CHoCH
🔸 Grade : *B* \\| Confidence: *78%*
🔸 Risk Tier: *0\\.5% 🟡*

✅ Konfluensi:
• Liquidity sweep M15 terkonfirmasi
• H1 bullish OB valid
• London session aktif

━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 *2\\-LAYER VALIDATION*

Layer 1 \\(POI Alert\\): ✅ TRIGGERED
Layer 2 \\(LTF Confirm\\): ✅ CONFIRMED
Candle Confirm: CHoCH M5 bullish confirmed

━━━━━━━━━━━━━━━━━━━━━━━━━━
💰 *EKSEKUSI*

📍 Entry : `2650\\.50`
🛡 SL : `2642\\.00` \\(85 pips\\)
🎯 TP : `2670\\.00` \\(195 pips\\)
⚖️ R:R : *1:2\\.29*
🛡 HTF SL: H1 invalidation below 2640

━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 *REASONING*
XAUUSD bullish setelah M15 sweep. H1 OB 2645\\-2650 valid. DXY weakening mendukung. London session optimal\\. R:R 1:2\\.29 valid\\.

━━━━━━━━━━━━━━━━━━━━━━━━━━
⚙️ MT5: ✅ READY TO FIRE
⏱ Cycle: `phantomfx_20260603T013500`

_"High Timeframe for Direction, Low Timeframe for Precision\\."_
⚠️ _Sinyal referensi institusional\\. Eksekusi final di tangan trader\\._

\\#PhantomFX \\#XAUUSD \\#SNIPER \\#B \\#Forex
---TELEGRAM_SIGNAL_END---

---TELEGRAM_KILLZONE_START---
📡 *KILLZONE ALERT — PhantomFX*

🕐 *LONDON SESSION AKTIF*
_Smart money paling agresif bergerak\\. Volatilitas optimal\\._

⚡ *Combat Style Recommended:*
→ COMMANDO: D1 bias jelas, London volatility support

🎯 *Key Levels to Watch:*
• XAUUSD: Alert zone 2645\\-2650 \\(BUY setup\\)

⏱ Session valid: 09:00 – 11:00 WIB
\\#Killzone \\#PhantomFX \\#London
---TELEGRAM_KILLZONE_END---
"""

SAMPLE_HOLD_SIGNAL = """
```json
{
 "system": "PhantomFX | GENESIS AI Trader v4.0",
 "cycle_id": "phantomfx_20260603T020000",
 "session": "Asian",
 "killzone_active": false,
 "circuit_breaker": false,
 "loss_count_today": 1,
 "combat_style": "HOLD",
 "style_reason": "Asian session — market choppy, no clear structure",
 "reflection": "N/A — no recent trades to reflect on",
 "symbol": "XAUUSD",
 "strategy": "N/A",
 "skc_score": {"s_struktur": 1.5, "k_konfluensi": 1.0, "c_konteks": 1.0, "total": 3.5, "zone": "RED"},
 "confluences": [],
 "layer_1_status": "N/A",
 "layer_2_status": "N/A",
 "action": "HOLD",
 "entry": 0, "sl": 0, "tp": 0,
 "sl_pips": 0, "tp_pips": 0,
 "rr_ratio": "N/A",
 "rr_valid": false,
 "risk_tier": "SKIP",
 "risk_zone": "RED",
 "confidence": 0.20,
 "grade": "D",
 "htf_sl_level": "N/A",
 "reasoning": "Asian session typically lacks conviction moves. SKC 3.5/10 (RED zone). Market ranging without clear structure across multiple TFs. No macro catalysts. Better to preserve capital and wait for London session.",
 "mt5_webhook": {"ready": false, "symbol": "XAUUSD", "type": "SKIP", "price": 0, "sl": 0, "tp": 0, "risk_percent": 0, "comment": "HOLD"},
 "notify_telegram": false
}
```
"""

SAMPLE_CIRCUIT_BREAKER = """
```json
{
 "system": "PhantomFX | GENESIS AI Trader v4.0",
 "cycle_id": "phantomfx_20260603T030000",
 "session": "Asian",
 "killzone_active": false,
 "circuit_breaker": true,
 "loss_count_today": 3,
 "combat_style": "HOLD",
 "style_reason": "CIRCUIT BREAKER ACTIVE — 3x consecutive losses",
 "action": "HOLD",
 "reason": "CIRCUIT_BREAKER_3X_LOSS",
 "notify_telegram": true
}
```

---TELEGRAM_CIRCUIT_START---
🔴 *CIRCUIT BREAKER AKTIF — PhantomFX*

⚠️ *3x Loss Berturut\\-turut Terdeteksi\\.*

Setelah 3x loss, otak tidak lagi berpikir logis\\.
Revenge trading = kehancuran modal\\.

*PhantomFX menghentikan semua analisis untuk hari ini\\.*

✅ *Apa yang harus dilakukan:*
• Tutup platform trading
• Review journal — bukan chart
• Istirahat mental
• Kembali besok dengan mindset segar

_"Musuh terbesar setelah 3x loss bukan market, tapi otak Anda\\."_
\\#CircuitBreaker \\#PhantomFX \\#CapitalProtection
---TELEGRAM_CIRCUIT_END---
"""


def test_parse_buy_signal():
    """Test parsing a BUY signal."""
    print("\n" + "="*60)
    print("TEST 1: Parse BUY Signal")
    print("="*60)
    
    parsed = parse_phantomfx_output(SAMPLE_BUY_SIGNAL)
    assert parsed is not None, "Failed to parse JSON"
    assert parsed["action"] == "BUY"
    assert parsed["symbol"] == "XAUUSD"
    assert parsed["entry"] == 2650.50
    assert parsed["skc_score"]["total"] == 8.5
    assert parsed["rr_ratio"] == "1:2.29"
    assert parsed["mt5_webhook"]["ready"] == True
    print("✅ JSON parsed correctly")
    print(f"   Action: {parsed['action']} {parsed['symbol']}")
    print(f"   Entry: {parsed['entry']} | SL: {parsed['sl']} | TP: {parsed['tp']}")
    print(f"   SKC: {parsed['skc_score']['total']}/10 ({parsed['skc_score']['zone']})")
    print(f"   R:R: {parsed['rr_ratio']} | Grade: {parsed['grade']}")
    
    signal = extract_telegram_signal(SAMPLE_BUY_SIGNAL)
    assert signal is not None, "Failed to extract Telegram signal"
    print("✅ Telegram signal extracted")
    
    killzone = extract_killzone_broadcast(SAMPLE_BUY_SIGNAL)
    assert killzone is not None, "Failed to extract killzone broadcast"
    print("✅ Killzone broadcast extracted")
    
    return True


def test_parse_hold_signal():
    """Test parsing a HOLD signal."""
    print("\n" + "="*60)
    print("TEST 2: Parse HOLD Signal")
    print("="*60)
    
    parsed = parse_phantomfx_output(SAMPLE_HOLD_SIGNAL)
    assert parsed is not None, "Failed to parse JSON"
    assert parsed["action"] == "HOLD"
    assert parsed["grade"] == "D"
    assert parsed["skc_score"]["zone"] == "RED"
    print("✅ HOLD signal parsed correctly")
    print(f"   Reason: {parsed['combat_style']} | SKC: {parsed['skc_score']['total']}/10")
    
    return True


def test_parse_circuit_breaker():
    """Test parsing a circuit breaker signal."""
    print("\n" + "="*60)
    print("TEST 3: Parse Circuit Breaker Signal")
    print("="*60)
    
    parsed = parse_phantomfx_output(SAMPLE_CIRCUIT_BREAKER)
    assert parsed is not None, "Failed to parse JSON"
    assert parsed["circuit_breaker"] == True
    assert parsed["action"] == "HOLD"
    assert parsed["loss_count_today"] == 3
    print("✅ Circuit breaker parsed correctly")
    
    circuit_msg = extract_circuit_alert(SAMPLE_CIRCUIT_BREAKER)
    assert circuit_msg is not None, "Failed to extract circuit alert"
    print("✅ Circuit breaker alert extracted")
    
    return True


def test_connector_process_buy(dry_run=True):
    """Test full connector processing with BUY signal."""
    print("\n" + "="*60)
    print("TEST 4: Connector Process BUY (Dry Run)")
    print("="*60)
    
    result = process_output(SAMPLE_BUY_SIGNAL, dry_run=dry_run, telegram_only=True)
    print(f"   Result: {json.dumps(result, indent=2)}")
    assert result["parsed"] == True, "Failed to parse"
    print("✅ Connector processed BUY signal correctly")
    
    return True


def test_connector_process_hold():
    """Test connector processing with HOLD signal."""
    print("\n" + "="*60)
    print("TEST 5: Connector Process HOLD")
    print("="*60)
    
    result = process_output(SAMPLE_HOLD_SIGNAL, dry_run=True, telegram_only=True)
    print(f"   Result: {json.dumps(result, indent=2)}")
    assert result["parsed"] == True
    print("✅ Connector processed HOLD signal correctly (MT5 skipped)")
    
    return True


def test_connector_process_circuit():
    """Test connector processing with circuit breaker."""
    print("\n" + "="*60)
    print("TEST 6: Connector Process Circuit Breaker")
    print("="*60)
    
    result = process_output(SAMPLE_CIRCUIT_BREAKER, dry_run=True, telegram_only=True)
    print(f"   Result: {json.dumps(result, indent=2)}")
    assert result["parsed"] == True
    assert "Circuit breaker active" in result["details"]
    print("✅ Circuit breaker correctly blocked MT5 execution")
    
    return True


def main():
    """Run all tests."""
    print("╔══════════════════════════════════════════════════╗")
    print("║  PhantomFX Integration Test Suite               ║")
    print("╚══════════════════════════════════════════════════╝")
    
    tests = [
        ("Parse BUY Signal", test_parse_buy_signal),
        ("Parse HOLD Signal", test_parse_hold_signal),
        ("Parse Circuit Breaker", test_parse_circuit_breaker),
        ("Process BUY (Dry Run)", lambda: test_connector_process_buy(dry_run=True)),
        ("Process HOLD", test_connector_process_hold),
        ("Process Circuit Breaker", test_connector_process_circuit),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"❌ FAILED: {name}")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
