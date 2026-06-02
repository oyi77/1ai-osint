# PhantomFX User Prompt Template
# This template is filled by the n8n workflow or connector script each cycle

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 AGENT: {{AGENT_ID}} | Cycle: {{TIMESTAMP}}
💰 Balance: ${{BALANCE}} | Equity: ${{EQUITY}} | DD: {{DRAWDOWN}}%
⚖️ Risk Mode: {{RISK_MODE}} | Session: {{SESSION}}
📡 Killzone: {{KILLZONE_STATUS}}
🔴 Circuit Breaker: Loss hari ini: {{LOSS_COUNT_TODAY}}/3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[⚠️ CIRCUIT BREAKER CHECK — PROSES INI PERTAMA]
Jika {{LOSS_COUNT_TODAY}} >= 3:
→ Output LANGSUNG: {"action":"HOLD","reason":"CIRCUIT_BREAKER_3X_LOSS","notify_telegram":true}
→ BERHENTI. Jangan proses apapun lagi.
Jika < 3: Lanjut ke analisis di bawah.


════════════════════════════════════════
🧠 LAST TRADE REFLECTION
════════════════════════════════════════
Result: {{LAST_TRADE_RESULT}} | Mode: {{LAST_MODE}} | Risk Tier: {{LAST_RISK_TIER}}
Symbol: {{LAST_SYMBOL}} | Action: {{LAST_ACTION}} | PnL: ${{LAST_PNL}}
Entry: {{LAST_ENTRY}} | Close: {{LAST_CLOSE}} | SL: {{LAST_SL}} | TP: {{LAST_TP}}
SKC Score saat entry: {{LAST_SKC_SCORE}} | Grade: {{LAST_GRADE}}

📝 REFLECTION RULES (NO HALLUCINATION):
- Analisis dari angka aktual di atas saja
- SL hit? → Kenapa? (Bias salah? SL terlalu tight? News surprise?)
- Apakah SKC Score sudah sesuai dengan hasil actual?
- Pelajaran apa untuk siklus berikutnya?
- Output: 2-3 kalimat SINGKAT FAKTUAL


════════════════════════════════════════
🌍 MARKET INTELLIGENCE — MACRO & NEWS
════════════════════════════════════════
📊 MACRO INTERNALS:
DXY: {{DXY_VALUE}} ({{DXY_CHANGE}}%) — {{DXY_INTERPRETATION}}
SPX: {{SPX_VALUE}} ({{SPX_CHANGE}}%)
VIX: {{VIX_VALUE}} — {{RISK_SENTIMENT}}
OIL_WTI: {{OIL_WTI_VALUE}} ({{OIL_WTI_CHANGE}}%)
US10Y: {{US10Y_VALUE}} ({{US10Y_CHANGE}}%)
GOLD: {{GOLD_FUT_VALUE}} ({{GOLD_FUT_CHANGE}}%)
REAL_YIELD: {{REAL_YIELD_SITUATION}}

📅 ECONOMIC CALENDAR (Today):
{{ECONOMIC_EVENTS}}

📰 RECENT HEADLINES (Last 2h):
{{RECENT_HEADLINES}}

📡 KILLZONE STATUS:
London (09:00-11:00 WIB): {{LONDON_KZ_STATUS}}
NY (20:00-22:00 WIB): {{NY_KZ_STATUS}}
Next Event: {{NEXT_NEWS_EVENT}} @ {{NEXT_NEWS_TIME}}

👁️ GPT-5 VISION INPUT (Optional):
{{CHART_SCREENSHOT_ANALYSIS}}


════════════════════════════════════════
📊 ASSET MENU — SCREENING 7-TF
════════════════════════════════════════
{{#each ASSETS}}
────────────────────────────────────────
🔥 PAIR: {{SYMBOL}} | Price: {{CURRENT_PRICE}}

BIAS SUMMARY:
 W1 Bias: {{W1_BIAS}} | Key: {{W1_LEVEL}}
 D1 Bias: {{D1_BIAS}} | Structure: {{D1_STRUCTURE}}
 H4 Bias: {{H4_BIAS}} | CHoCH/BOS: {{H4_STRUCTURE}} | POI: {{H4_POI}}
 H1 POI: {{H1_POI}} | FVG Zone: {{H1_FVG}}
 M15 Trend: {{M15_TREND}} | Range: {{M15_RANGE}} pips
 Support: {{M5_SUPPORT}} | Resistance: {{M5_RESISTANCE}}

H4 (Last 5 candles):
Time | Open | High | Low | Close |
{{H4_CANDLES}}

H1 (Last 10 candles):
Time | Open | High | Low | Close |
{{H1_CANDLES}}

M15 (Last 10 candles):
Time | Open | High | Low | Close |
{{M15_CANDLES}}

M5 (Last 10 candles):
Time | Open | High | Low | Close |
{{M5_CANDLES}}
{{/each}}


NOW OUTPUT YOUR DECISION:
Follow the TRIPLE OUTPUT FORMAT (System JSON + Telegram Signal + Killzone Broadcast + Circuit Alert if applicable).
