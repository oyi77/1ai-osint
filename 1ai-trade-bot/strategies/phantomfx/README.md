# PhantomFX | GENESIS AI Trader v4.0 — Implementation

> Selesai dibangun: Skill, Connector, MT5 EA, n8n Workflow, Test Suite
> Semua file di `~/projects/1ai-trade-bot/strategies/phantomfx/`

## Struktur File

```
strategies/phantomfx/
├── SKILL.md                          # OpenClaw skill definition + commands
├── test_phantomfx.py                 # Integration test (6/6 PASSED ✅)
├── prompts/
│   ├── system_prompt.md              # System prompt untuk OpenClaw agent
│   └── user_prompt_template.md       # Template diisi otomatis tiap cycle
├── mt5/
│   └── PhantomFX_Webhook_EA.mq5      # MT5 Expert Advisor (HTTP webhook server)
├── n8n/
│   └── phantomfx_workflow.json       # n8n workflow (15-min schedule)
scripts/
└── phantomfx_connector.py            # Bridge: OpenClaw → MT5 Router + Telegram
```

## OpenClaw Commands

| Command | Fungsi |
|---------|--------|
| `/phantomfx` | Full analysis cycle: circuit breaker → combat style → SKC → 2-layer validation → signal |
| `/phantomfx quick XAUUSD` | Quick analysis tanpa full prompt |
| `/phantomfx session` | Status: balance, equity, DD, loss count, killzone |
| `/killzone` | Cek killzone (London/NY) dan broadcast alert |
| `/reflect` | Refleksi last trade & pelajaran |

## Arsitektur

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│  OpenClaw    │────▶│ PhantomFX       │────▶│ MT5 Router   │
│  /phantomfx  │     │ Connector (Py)  │     │ API :8080    │
│              │     │ scripts/        │     │              │
│              │     │ phantomfx_      │     │ webhooks/    │
│              │     │ connector.py    │     │ receive      │
└──────────────┘     └──────┬──────────┘     └──────┬───────┘
                            │                       │
                            ▼                       ▼
                     ┌──────────────┐     ┌──────────────────┐
                     │  Telegram    │     │  MT5 Terminal    │
                     │ @berkahkarya │     │  PhantomFX EA    │
                     │ forexbotbot  │     │  (Webhook EA)    │
                     └──────────────┘     └──────────────────┘
```

**ALT path (Direct EA):** Connector bisa POST langsung ke PhantomFX EA di MT5 (port 8765) tanpa lewat MT5 Router.

## Cara Deploy

### 1. MT5 Webhook EA
- Copy `mt5/PhantomFX_Webhook_EA.mq5` ke MT5 → Experts folder
- Compile di MetaEditor (F7)
- Attach ke chart XAUUSD M5
- EA listens on port 8765, token `phantomfx`

### 2. PhantomFX Connector
```bash
# Set environment variables
export MT5_ROUTER_URL="http://localhost:8080"
export MT5_ROUTER_API_KEY="your_key"
export MT5_INSTANCE_ID="mt5-default"
export PHANTOMFX_TELEGRAM_BOT_TOKEN="bot_token"
export PHANTOMFX_TELEGRAM_CHAT_ID="@berkahkaryaforexbotbot"

# Pipe OpenClaw output:
echo '{phantomfx_json}' | python3 scripts/phantomfx_connector.py

# Or from file:
python3 scripts/phantomfx_connector.py --input phantomfx_output.txt
```

### 3. n8n Workflow (Scheduled Mode)
- Import `n8n/phantomfx_workflow.json` ke n8n
- Set env variables di n8n: `MT5_ROUTER_URL`, `MT5_ROUTER_API_KEY`, `OPENCLAW_API_URL`, `OPENCLAW_API_KEY`, `PHANTOMFX_TELEGRAM_BOT_TOKEN`, `PHANTOMFX_TELEGRAM_CHAT_ID`
- Activate workflow → runs every 15 min

### 4. OpenClaw Skill
- Udah live: trigger `/phantomfx` kapan aja
- Skill auto-activates saat mention PhantomFX, trading signals, killzone, MT5

## Test Results

```
✅ Parse BUY Signal       — JSON + Telegram + Killzone extracted
✅ Parse HOLD Signal      — HOLD detected, MT5 skipped  
✅ Parse Circuit Breaker  — CB triggered, all trading blocked
✅ Process BUY (Dry Run)  — Connector routing correct
✅ Process HOLD           — MT5 correctly skipped
✅ Process Circuit Breaker — Emergency stop works

6/6 PASSED
```

## Telegram Bot (@berkahkaryaforexbotbot)

Signal format yang dikirim:
- ⚡ **Combat Style** + alasan
- 🔬 **SKC Score** dengan breakdown S/K/C
- 📊 **Entry/SL/TP** + R:R
- 🌍 **Macro snapshot** (DXY, VIX)
- 🧠 **Reasoning** 4-5 kalimat
- 📜 **Last trade reflection**
- ⚙️ **MT5 Ready to Fire** status

## Quick Start (one-liner test)
```bash
cd ~/projects/1ai-trade-bot
python3 strategies/phantomfx/test_phantomfx.py
```
