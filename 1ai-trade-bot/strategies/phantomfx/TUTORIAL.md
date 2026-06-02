# PhantomFX EA — Compile & Install Tutorial

> ⚡ PhantomFX | GENESIS AI Trader v4.0  
> MT5 Expert Advisor Installation Guide

---

## 📋 Prasyarat

- MetaTrader 5 (MT5) sudah terinstall
- Akun MT5 (real atau demo) terhubung ke broker
- File `PhantomFX_Webhook_EA.mq5` (sumber kode)

---

## 🔧 Step 1: Copy EA ke Folder MT5

Buka folder MT5:

```
File → Open Data Folder → MQL5 → Experts
```

Copy `PhantomFX_Webhook_EA.mq5` ke folder `Experts/PhantomFX/`.

```
MQL5/
└── Experts/
    └── PhantomFX/
        └── PhantomFX_Webhook_EA.mq5
```

---

## ⚙️ Step 2: Compile di MetaEditor

1. **Buka MetaEditor**:
   - Di MT5: klik `Tools → MetaQuotes Language Editor` (atau F4)
   - Atau klik kanan EA di Navigator → `Modify`

2. **Buka file**:
   - `File → Open` → cari `PhantomFX_Webhook_EA.mq5`

3. **Compile**:
   - Klik `Compile` (F7) di toolbar
   - Tunggu sampai muncul: `0 errors, 0 warnings`
   - File `.ex5` otomatis dibuat di folder yang sama

4. **Verifikasi**:
   - Di tab `Navigator` MT5, refresh (klik kanan → Refresh)
   - `PhantomFX_Webhook_EA` muncul di bawah `Expert Advisors`

> ⚠️ **Kalau error waktu compile:** Pastikan MT5 versi terbaru. EA ini pakai `SocketCreate()` yang ada sejak MT5 build 3500+.

---

## 📊 Step 3: Attach EA ke Chart

1. **Buka chart XAUUSD M5** (Gold, timeframe 5 menit)
2. **Drag PhantomFX_Webhook_EA** dari Navigator ke chart
3. Atau double-click EA di Navigator

4. **Setting Input Parameters:**

| Parameter | Default | Keterangan |
|-----------|---------|------------|
| WebhookPort | `8765` | Port HTTP untuk terima sinyal |
| WebhookToken | `phantomfx` | Token auth (ganti untuk security) |
| EnableSSL | `false` | SSL (biarkan false) |
| DefaultRiskPercent | `1.0` | Risk default per trade (%) |
| MaxRiskPercent | `2.0` | Risk maksimum (%) |
| MinRRRatio | `1.5` | Minimum R:R ratio |
| MagicNumber | `234000` | EA Magic Number (identifikasi trade) |
| FilterSessions | `true` | Filter by session |
| TradeAsian | `false` | Izinkan Asian session |
| TradeLondon | `true` | Izinkan London session |
| TradeNY | `true` | Izinkan NY session |
| MaxDailyLosses | `3` | Max loss berurutan sebelum CB |
| MaxDailyDrawdown | `5.0` | Max daily DD % sebelum halt |

5. **Tab "Common"** — centang:
   - ✅ Allow Algo Trading
   - ✅ Allow WebRequest for listed URL (tambahkan `http://localhost:8765`)

6. **Klik OK**

7. **Pastikan AutoTrading ON** di toolbar MT5 (ikon hijau)

---

## 🟢 Step 4: Verifikasi EA Running

1. Lihat **pojok kanan atas chart** — harus ada nama EA + smiley face
2. Klik chart — popup status muncul:
   ```
   ⚡ PhantomFX EA v4.0
   ──────────────────────
   Port: 8765 | Token: phantomfx
   Balance: $XXX | Losses: 0/3
   Daily P&L: $0.00 | DD: 0.00%
   ──────────────────────
   Status: 🟢 LISTENING
   ```

3. **Test koneksi dari terminal:**
   ```bash
   curl -X POST http://localhost:8765/ \
     -H "Authorization: Bearer phantomfx" \
     -H "Content-Type: application/json" \
     -d '{"symbol":"XAUUSD","type":"SKIP","price":0,"sl":0,"tp":0,"risk_percent":0,"comment":"test"}'
   ```
   Harus return: `{"status":"executed","timestamp":...}`

---

## 🔗 Step 5: Connect ke PhantomFX Connector

Di connector, set environment variable:

```bash
# Untuk direct EA (tanpa MT5 Router):
export MT5_EA_WEBHOOK_URL="http://localhost:8765"
export MT5_EA_WEBHOOK_TOKEN="phantomfx"
```

Atau edit `.env` di `strategies/phantomfx/.env`.

---

## 🧪 Step 6: Test Full Pipeline

```bash
cd ~/projects/1ai-trade-bot

# Test connector dengan sample signal
python3 scripts/phantomfx_connector.py --dry-run \
  --input strategies/phantomfx/test_data/sample_buy.json

# Running semua test
python3 strategies/phantomfx/test_phantomfx.py
```

---

## 🛡️ Circuit Breaker

EA otomatis menghentikan trading jika:
- **3x loss berurutan** dalam 1 hari
- **Daily drawdown > 5%**

Reset otomatis jam 00:00 (midnight).

---

## 📡 Webhook Payload Format

EA menerima HTTP POST dengan JSON body:

```json
{
  "symbol": "XAUUSD",
  "type": "OP_BUY",
  "price": 2650.50,
  "sl": 2642.00,
  "tp": 2670.00,
  "risk_percent": 1.0,
  "comment": "PhantomFX_SNIPER_A_20260603T013500"
}
```

| Field | Type | Keterangan |
|-------|------|------------|
| `symbol` | string | Pair (XAUUSD, EURUSD, etc) |
| `type` | string | `OP_BUY`, `OP_SELL`, `SKIP`, `HOLD` |
| `price` | float | Entry price (0 = market execution) |
| `sl` | float | Stop Loss |
| `tp` | float | Take Profit |
| `risk_percent` | float | Risk % per trade |
| `comment` | string | Comment di trade history |

---

## 🔍 Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `SocketCreate failed` | MT5 versi lama → update ke build 3500+ |
| `Symbol not found` | Nama pair salah → cek Market Watch |
| `Trade blocked (circuit breaker)` | Loss count ≥ 3 → tunggu besok |
| `Trade blocked (session)` | Di luar London/NY → enable TradeAsian |
| `OrderSend failed` | Cek balance, margin, atau broker restriksi |
| EA ga muncul di Navigator | Refresh Navigator, restart MT5 |

---

## 📁 Files

| File | Path |
|------|------|
| Source Code | `PhantomFX_Webhook_EA.mq5` |
| Compiled EA | `PhantomFX_Webhook_EA.ex5` (setelah compile) |
| Connector | `scripts/phantomfx_connector.py` |
| n8n Workflow | `strategies/phantomfx/n8n/phantomfx_workflow.json` |

---

*PhantomFX — "High Timeframe for Direction, Low Timeframe for Precision."*
