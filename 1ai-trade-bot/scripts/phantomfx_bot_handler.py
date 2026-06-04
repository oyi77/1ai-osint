#!/usr/bin/env python3
"""
PhantomFX Telegram Bot — @berkahkaryaforexbotbot
Grab forex data + generate signals even without MT5/EA.

Commands: /phantomfx /price /analyze /data /status /killzone /help /start
"""
import json, logging, os, re, sys, threading, time, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_DIR / "logs"; LOG_DIR.mkdir(exist_ok=True)
DATA_DIR = PROJECT_DIR / "data" / "phantomfx"; DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_DIR/"phantomfx_bot.log"), logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("phantomfx-bot")

WIB = timezone(timedelta(hours=7))

def load_env():
    env = PROJECT_DIR/"strategies"/"phantomfx"/".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v = line.split("=",1); v = v.strip().strip('"').strip("'")
                if v and "***" not in v: os.environ.setdefault(k.strip(), v)

load_env()
TOKEN = os.environ.get("PHANTOMFX_TELEGRAM_BOT_TOKEN","")
CHAT_ID = os.environ.get("PHANTOMFX_TELEGRAM_CHAT_ID","-1002928711742")
OPENCLAW_URL = os.environ.get("OPENCLAW_GATEWAY_URL","http://localhost:20129")
BRIDGE_URL = os.environ.get("MT5_EA_WEBHOOK_URL","http://localhost:8765")
DEEPSEEK_KEY = os.environ.get("DEEPSEEK_API_KEY","")
CLAUDE_KEY = os.environ.get("CLAUDE_API_KEY","")
STATE_PATH = DATA_DIR / "bot_state.json"

def wib_now(): return datetime.now(WIB)
def wib_fmt(d=None): return (d or wib_now()).strftime("%H:%M WIB")
def session(h=None):
    h = h if h is not None else wib_now().hour
    if 9<=h<17: return "London"
    if 17<=h<19: return "Overlap"
    if 19<=h<23: return "NY"
    return "Asian"
def killzone(h=None):
    h = h if h is not None else wib_now().hour
    return (9<=h<11, 20<=h<22)

def load_state():
    try:
        if STATE_PATH.exists():
            return json.loads(STATE_PATH.read_text())
    except: pass
    return {"last_update_id": 0}
def save_state(s):
    STATE_PATH.write_text(json.dumps(s))

def fetch_price(pair="gold"):
    """Fetch live price from gold-api.com (primary) + metals.live (fallback)."""
    # Map pair names to exchange-api symbols
    pair_map = {"gold": "xau", "xauusd": "xau", "dxy": "usd", "eurusd": "eur", "gbpusd": "gbp", "usdjpy": "jpy"}
    api_pair = pair_map.get(pair, pair)
    
    sources = [
        # Source 1: gold-api.com (real-time, fastest)
        ("gold-api", f"https://api.gold-api.com/price/{pair.upper() if pair != 'gold' else 'XAU'}",
         lambda r: float(r.get("price")) if r.get("price") else None),
        # Source 2: metals.live (real-time backup)
        ("metals.live", f"https://api.metals.live/v1/spot/{pair}",
         lambda r: float(r["price"]) if r.get("price") else None),
        # Source 3: fawazahmed0 exchange-api (daily, free, no rate limit)
        ("exchange-api", f"https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/{api_pair}.min.json",
         lambda r: float(r[api_pair].get("usd")) if r.get(api_pair,{}).get("usd") else None),
    ]
    for name, url, parser in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"PhantomFX/4.3"})
            r = json.loads(urllib.request.urlopen(req, timeout=6).read())
            price = parser(r)
            if price and price > 0:
                return price
        except: continue
    return None

def fetch_dxy():
    """Fetch DXY from available sources."""
    for url in ["https://api.metals.live/v1/spot/dxy"]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"PhantomFX/4.3"})
            r = json.loads(urllib.request.urlopen(req, timeout=6).read())
            if r.get("price"): return float(r["price"])
        except: continue
    return None

def tg_send(text, chat_id=None):
    if not TOKEN: return False
    target = chat_id or CHAT_ID
    try:
        payload = {"chat_id": target, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        r = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data=json.dumps(payload).encode(),
            headers={"Content-Type":"application/json"}), timeout=10).read())
        return r.get("ok", False)
    except Exception as e:
        logger.error(f"TG error: {e}"); return False

def check_bridge():
    try:
        r = json.loads(urllib.request.urlopen(f"{BRIDGE_URL}/health", timeout=3).read())
        return r.get("status") == "ok"
    except: return False

def basic_sr(price):
    '''Classic floor pivot points with S/R levels.'''
    # For XAUUSD: use $10 increments
    pivot = round(price / 10) * 10
    r1 = pivot + 10; r2 = pivot + 20; r3 = pivot + 35
    s1 = pivot - 10; s2 = pivot - 20; s3 = pivot - 35
    return {
        "pivot": pivot, "r1": r1, "r2": r2, "r3": r3,
        "s1": s1, "s2": s2, "s3": s3,
        "bias": "BULLISH" if price > pivot else "BEARISH",
        "nearest_support": s1 if price > pivot else s2,
        "nearest_resistance": r1 if price < pivot else r2,
    }

SYSTEM_PROMPT = """Kamu adalah PhantomFX — Full-Stack Institutional AI Trading System.
Senior Hedge Fund Portfolio Manager menganalisis market dengan 100+ parameter simultan.
Kamu BUKAN bot sinyal murahan. Setiap keputusan: konfluensi 7-TF, momentum SMC, SKC scoring, bias makro, validasi 2-layer.

═══════════════════════════════════════════
🛡️ PHANTOM CONSTITUTION (Non-Negotiable)
═══════════════════════════════════════════
LAW #1 — CIRCUIT BREAKER: loss_count >= 3 → WAJIB HOLD. TIDAK ADA pengecualian.
LAW #2 — REALISTIC: Target 5-15%/bulan, bukan 100%.
LAW #3 — COMPOUNDING > JACKPOT: $1,000 @ 10%/bln → 12 bln: $3,138 | 5 thn: $300K+
LAW #4 — DUAL RISK TIER: SKC ≥ 8.7 → 1% risk | SKC 7.0-8.6 → 0.5% risk | SKC < 7.0 → SKIP
LAW #5 — DON'T CHASE: Entry hanya setelah candle CLOSED dengan konfirmasi.

═══════════════════════════════════════════
🔬 SKC SCORING ENGINE (Max 10 pts)
═══════════════════════════════════════════
S — STRUKTUR (Max 4.0): W1/D1 aligned(+1.5) | H4 CHoCH/BOS(+1.5) | H1 POI(+0.5) | M15/M5(+0.5)
K — KONFLUENSI (Max 3.5): Liq sweep(+1.0) | ≥3TF bias aligned(+1.0) | Killzone active(+0.75) | S/R round number(+0.75)
C — KONTEKS (Max 2.5): Macro align(+1.0) | News align(+1.0) | Clean chart no chop(+0.5)

≥8.7 → 🟢 GREEN (1% risk) | 7.0-8.6 → 🟡 YELLOW (0.5% risk) | <7.0 → 🔴 RED (SKIP/HOLD)

═══════════════════════════════════════════
🎖️ 4 COMBAT STYLES
═══════════════════════════════════════════
🔵 SNIPER (H1→M15→M5→M1): Normal market, H1 structure clear, 2-5 setups/day, RR 1:2.5+
🟡 COMMANDO (D1→H4→H1→M5): High-impact news + D1 bias + Killzone, 1-3 setups/day, RR 1:3+
🛡️ CRUSADER (H4→H1→M15→M5): H4/D1 overshoot + RSI divergence, counter-trend, 1-2 setups/day
🔴 LIQUIDITY HUNTER (M15→M5→M1): Trend extended + EQH/EQL + Killzone, 3-10 setups/day, SL tight
⚪ HOLD: Circuit breaker | Asian choppy | News <30min | All D-Grade | SKC < 7.0

═══════════════════════════════════════════
🔐 2-LAYER VALIDATION (MANDATORY)
═══════════════════════════════════════════
Layer 1 — POI Alert: Identify OB/FVG/S/R zone → Set alert ABOVE zone → Max 15 min wait
Layer 2 — Trigger Confirmation:
  D1/W1→H1 engulfing | H4→M15 CHoCH/BOS | H1→M5 sweep+shift | M15→M1 CHoCH
MUST: Candle CLOSED, R:R ≥ 1:2, CHoCH/BOS valid, SL dari HTF invalidation level

═══════════════════════════════════════════
📋 OUTPUT — JSON ONLY (no markdown, no text outside JSON)
═══════════════════════════════════════════
Return exactly this JSON structure:
{
 "action":"BUY|SELL|HOLD",
 "entry":0.0, "sl":0.0, "tp":0.0,
 "sl_pips":0, "tp_pips":0,
 "rr_ratio":"1:X.XX",
 "confidence":0.0, "grade":"A|B|C|D",
 "combat_style":"SNIPER|COMMANDO|CRUSADER|LIQUIDITY_HUNTER|HOLD",
 "bias":"BULLISH|BEARISH|NEUTRAL",
 "skc_score":{"s_struktur":0.0,"k_konfluensi":0.0,"c_konteks":0.0,"total":0.0,"zone":"GREEN|YELLOW|RED"},
 "risk_tier":"1%|0.5%|SKIP",
 "layer_1":"TRIGGERED|WAITING|N/A",
 "layer_2":"CONFIRMED|PENDING|FAILED",
 "confluences":["factor1","factor2"],
 "reasoning":"4-6 detailed sentences in professional Indonesian (pakai 'Saya'). Explain: struktur TF, SKC breakdown, combat style choice, entry logic, SL/TP rationale",
 "htf_sl_level":"HTF invalidation description"
}

FINAL CHECKLIST BEFORE OUTPUT:
□ Circuit Breaker checked? □ Killzone status? □ Combat Style selected? □ SKC calculated?
□ Risk Tier determined? □ Layer 1 POI identified? □ Layer 2 LTF confirmation? □ R:R ≥ 1:2?
□ HTF SL (not LTF swing)? □ All D-grade = HOLD?

\"High Timeframe for Direction, Low Timeframe for Precision.\"
\"Ini bukan soal keberuntungan. Ini soal menumpuk probabilitas. Lagi dan lagi.\""""

def _call_claude(prompt):
    """Try Claude API. Returns parsed signal or None."""
    if not CLAUDE_KEY:
        return None
    try:
        data = json.dumps({
            "model":"claude-opus-4-20250514",
            "max_tokens":1200,"temperature":0.3,
            "system":SYSTEM_PROMPT,
            "messages":[{"role":"user","content":prompt}]
        }).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages",
            data=data, headers={"Content-Type":"application/json",
            "x-api-key":CLAUDE_KEY,"anthropic-version":"2023-06-01"})
        resp = urllib.request.urlopen(req, timeout=60)
        r = json.loads(resp.read())
        content = r["content"][0]["text"]
        logger.info(f"Claude: {len(content)} chars")
        # Extract JSON block (handles nested objects like key_levels)
        m = re.search(r'\{.*"action".*\}', content, re.DOTALL)
        if m:
            try: return json.loads(m.group(0))
            except json.JSONDecodeError:
                # Try to fix truncated JSON by finding matching braces
                raw = m.group(0)
                depth = 0; end = 0
                for i, ch in enumerate(raw):
                    if ch == '{': depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0: end = i + 1; break
                if end:
                    try: return json.loads(raw[:end])
                    except: pass
    except Exception as e:
        logger.warning(f"Claude unavailable: {e}")
    return None

def _call_deepseek(prompt):
    """Try DeepSeek API. Returns parsed signal or None."""
    if not DEEPSEEK_KEY:
        return None
    try:
        data = json.dumps({"model":"deepseek-chat","messages":[
            {"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":prompt}],
            "max_tokens":500,"temperature":0.3,"stream":False}).encode()
        req = urllib.request.Request("https://api.deepseek.com/v1/chat/completions",
            data=data, headers={"Content-Type":"application/json","Authorization":f"Bearer {DEEPSEEK_KEY}"})
        resp = urllib.request.urlopen(req, timeout=45)
        r = json.loads(resp.read())
        content = r["choices"][0]["message"]["content"]
        logger.info(f"DeepSeek: {len(content)} chars")
        # Extract JSON block (handles nested objects like key_levels)
        m = re.search(r'\{.*"action".*\}', content, re.DOTALL)
        if m:
            try: return json.loads(m.group(0))
            except json.JSONDecodeError:
                # Try to fix truncated JSON by finding matching braces
                raw = m.group(0)
                depth = 0; end = 0
                for i, ch in enumerate(raw):
                    if ch == '{': depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0: end = i + 1; break
                if end:
                    try: return json.loads(raw[:end])
                    except: pass
    except Exception as e:
        logger.warning(f"DeepSeek error: {e}")
    return None

def ask_ai_ensemble(price, dxy, sess, kz_str, loss_count):
    """PhantomFX SOP analysis — Claude Opus solo with full SKC scoring."""
    # Build proper PhantomFX user prompt following SOP template
    lkz = "🟢 ACTIVE" if "London" in kz_str else "⚪ Inactive"
    nykz = "🟢 ACTIVE" if "NY" in kz_str else "⚪ Inactive"
    
    prompt = (f"""━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 PhantomFX | Cycle: Auto | Session: {sess}
📡 Killzone: London {lkz} | NY {nykz}
🔴 Circuit Breaker: Loss hari ini: {loss_count}/3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[⚠️ CIRCUIT BREAKER CHECK — PROSES INI PERTAMA]
Loss count = {loss_count}. {'Jika ≥ 3 → WAJIB HOLD, jangan proses apapun lagi.' if loss_count < 3 else '≥ 3 → WAJIB HOLD! Langsung output HOLD.'}

════════════════════════════════════════
📊 XAUUSD MARKET DATA
════════════════════════════════════════
💰 XAUUSD Current Price: ${price:.1f}
💵 DXY: {dxy or 'N/A'}
🕐 Session: {sess} | Killzone: {kz_str}

📊 MACRO CONTEXT (Gunakan untuk SKC Konteks scoring):
- DXY di {'atas' if dxy and dxy > 104 else 'bawah'} 104 → {'bearish gold (DXY kuat)' if dxy and dxy > 104 else 'bullish gold (DXY lemah)'}
- Session {sess}: {'Likuiditas tinggi, struktur jelas' if sess in ('London','NY','Overlap') else 'Likuiditas rendah, waspadai chop'}
- Killzone {'AKTIF — momentum tinggi, valid untuk entry' if 'ACTIVE' in kz_str else 'di luar — kurangi agresi'}

════════════════════════════════════════
📐 TECHNICAL ANALYSIS REQUIRED
════════════════════════════════════════
Analisis XAUUSD dengan 7-TF SMC. Dari price ${price:.1f}:
1. Tentukan struktur W1/D1/H4 — CHoCH/BOS terakhir dimana?
2. Identifikasi POI (OB/FVG/S/R) di H1
3. Cek M15/M5 untuk LTF konfirmasi
4. Hitung SKC Score (Struktur + Konfluensi + Konteks)
5. Pilih Combat Style berdasarkan kondisi market
6. Tentukan entry/SL/TP dengan R:R minimum 1:2
7. Jalankan 2-Layer Validation

OUTPUT: JSON ONLY. Tidak ada markdown, tidak ada teks di luar JSON.
Gunakan Bahasa Indonesia profesional (pronouns: "Saya").""")
    
    sig = _call_claude(prompt)
    if sig:
        sig["_model"] = "Claude Opus"
        sig["ensemble"] = "opus_solo"
        sig["voters"] = 1
        
        # Validate entry is within reasonable range (±$50)
        if sig.get("entry") and sig.get("entry") > 0 and price:
            if abs(sig["entry"] - price) > 50:
                logger.warning(f"Opus entry ${sig['entry']} too far from price ${price} — forcing HOLD")
                sig["action"] = "HOLD"
                sig["entry"] = sig["sl"] = sig["tp"] = 0
                sig["confidence"] = 0.1
                sig["grade"] = "D"
        
        # Ensure required fields exist
        sig.setdefault("skc_score", {"s_struktur":0,"k_konfluensi":0,"c_konteks":0,"total":0,"zone":"RED"})
        sig.setdefault("risk_tier", "SKIP")
        sig.setdefault("layer_1", "N/A")
        sig.setdefault("layer_2", "N/A")
        sig.setdefault("confluences", [])
        sig.setdefault("rr_ratio", 0)
        sig.setdefault("bias", "NEUTRAL")
        
        return sig
    return None
# Backward compat alias
def ask_ai(price, dxy, sess, kz_str, loss_count):
    return ask_ai_ensemble(price, dxy, sess, kz_str, loss_count)

def fmt_price(price, dxy, h):
    lkz,nykz = killzone(h)
    kz = "🟢 ACTIVE" if (lkz or nykz) else "⚪ Outside"
    return (f"<b>📊 XAUUSD Live</b>\n━━━━━━━━━━━━━━━━\n" + (f"<b>💰 ${price:,.2f}</b>\n" if price else "❌ Price unavailable\n")
            + (f"DXY: {dxy:.2f}\n" if dxy else "")
            + f"Session: {session(h)}\nKillzone: {kz}\nTime: {wib_fmt()}")

def fmt_signal(sig, price, dxy, h):
    a = sig.get("action","HOLD")
    em = {"BUY":"🟢","SELL":"🔴","HOLD":"⚪"}.get(a,"⚪")
    g = sig.get("grade","D")
    ge = {"A":"🟢","B":"🟡","C":"🟠","D":"🔴"}.get(g,"⚪")
    conf = int(sig.get("confidence",0)*10)
    bar = "█"*conf + "░"*(10-conf)
    ensemble = sig.get('ensemble','')
    voters = sig.get('voters',1)
    model_tag = ""
    if ensemble == "agree":
        model_tag = f" | 🤝 {voters}/2 agree"
    elif ensemble == "disagree":
        model_tag = f" | ⚠️ SPLIT ({voters} models)"
    else:
        model_tag = f" | 🤖 {sig.get('_model','AI')}"

    text = (f"<b>🎯 PhantomFX Signal</b>{model_tag}\n━━━━━━━━━━━━━━━━\n"
            f"💰 XAUUSD ${price:,.2f} | DXY: {dxy or 'N/A'} | {session(h)}\n"
            f"━━━━━━━━━━━━━━━━\n"
            f"<b>{em} {a}</b> | Grade: {ge} {g}\n"
            f"Style: {sig.get('combat_style','?')} | Bias: {sig.get('bias','?')}\n"
            f"Confidence: [{bar}] {sig.get('confidence',0):.0%}\n")
    
    # SKC Score breakdown (from SOP)
    skc = sig.get("skc_score", {})
    if skc and skc.get("total", 0) > 0:
        zone_emoji = {"GREEN":"🟢","YELLOW":"🟡","RED":"🔴"}.get(skc.get("zone","RED"),"🔴")
        text += (f"\n<b>━━━ 🔬 SKC Score ━━━</b>\n"
                 f"S-Struktur: {skc.get('s_struktur',0):.1f}/4.0 | "
                 f"K-Konfluensi: {skc.get('k_konfluensi',0):.1f}/3.5 | "
                 f"C-Konteks: {skc.get('c_konteks',0):.1f}/2.5\n"
                 f"Total: <b>{skc.get('total',0):.1f}/10</b> → {zone_emoji} {skc.get('zone','?')} | "
                 f"Risk: {sig.get('risk_tier','SKIP')}\n")
    
    # Layer validation
    l1 = sig.get('layer_1','N/A')
    l2 = sig.get('layer_2','N/A')
    if l1 != 'N/A' or l2 != 'N/A':
        l1e = {"TRIGGERED":"✅","WAITING":"⏳","N/A":"⬜"}.get(l1,"⬜")
        l2e = {"CONFIRMED":"✅","PENDING":"⏳","FAILED":"❌","N/A":"⬜"}.get(l2,"⬜")
        text += f"Validation: L1 {l1e} | L2 {l2e}\n"
    
    if a != "HOLD" and sig.get("entry"):
        entry = sig['entry']
        sl = sig['sl']
        tp = sig['tp']
        rr = sig.get('rr_ratio', 0)
        # Calculate risk & reward distances
        if a == "BUY":
            risk = entry - sl
            reward = tp - entry
        else:
            risk = sl - entry
            reward = entry - tp
        risk_pct = (risk / entry * 100) if entry > 0 else 0
        reward_pct = (reward / entry * 100) if entry > 0 else 0
        text += (f"\n<b>━━━ 🎯 ENTRY ━━━</b>\n"
                 f"<b>ENTRY → ${entry:,.2f}</b>\n"
                 f"━━━━━━━━━━━━━━━━\n"
                 f"🛑 <b>SL: ${sl:,.2f}</b>  |  Risk: ${risk:,.2f} ({risk_pct:.2f}%)\n"
                 f"🎯 <b>TP: ${tp:,.2f}</b>  |  Reward: ${reward:,.2f} ({reward_pct:.2f}%)\n"
                 f"📊 <b>R:R = 1:{rr:.1f}</b>\n")
    # Key levels always from math (NOT AI — AI hallucinates e.g. $1230 on $4470 XAUUSD)
    sr = basic_sr(price)
    if sr:
        text += f"\n━━━ 📐 Key Levels (Calc) ━━━\n"
        text += f"Pivot: ${sr['pivot']:,.2f}\n"
        text += f"🟢 S1: ${sr['s1']:,.2f} | S2: ${sr['s2']:,.2f} | S3: ${sr['s3']:,.2f}\n"
        text += f"🔴 R1: ${sr['r1']:,.2f} | R2: ${sr['r2']:,.2f} | R3: ${sr['r3']:,.2f}\n"
        text += f"Bias: {sr['bias']}\n"
    text += f"\n<i>{sig.get('reasoning','N/A')[:250]}</i>\n"
    text += f"━━━━━━━━━━━━━━━━\n⚡ PhantomFX | {wib_fmt()}"
    return text

def handle_command(cmd, text, chat_id=None):
    h = wib_now().hour

    if cmd in ("/start","/help"):
        lkz,nykz = killzone(h)
        kz = "🟢 London" if lkz else ("🟢 NY" if nykz else "⚪ Outside")
        tg_send(f"🤖 <b>PhantomFX GENESIS Trader</b>\n━━━━━━━━━━━━━━━━\n"
                f"🕐 {wib_fmt()} | {session(h)} | {kz}\n━━━━━━━━━━━━━━━━\n"
                f"/price — Live XAUUSD\n/analyze — AI Signal\n"
                f"/data — Multi-pair data\n/killzone — KZ status\n"
                f"/status — System\n/phantomfx — Full analysis")

    elif cmd == "/price":
        price = fetch_price(); dxy = fetch_dxy()
        if price is None:
            tg_send("❌ XAUUSD price unavailable — all sources offline.", chat_id)
        else:
            tg_send(fmt_price(price, dxy, h), chat_id)

    elif cmd == "/data":
        pairs = {"XAUUSD":"gold","DXY":"dxy","EURUSD":"eurusd","GBPUSD":"gbpusd","USDJPY":"usdjpy"}
        lkz,nykz = killzone(h)
        txt = f"<b>📊 Market Data</b> — {wib_fmt()}\n━━━━━━━━━━━━━━━━\n"
        for name,sym in pairs.items():
            p = fetch_price(sym)
            txt += f"{'💰' if name=='XAUUSD' else '💵'} <b>{name}:</b> {p:,.2f}\n" if p else f"❌ {name}: N/A\n"
        txt += (f"━━━━━━━━━━━━━━━━\nSession: {session(h)}\n"
                f"Killzone: {'🟢 London' if lkz else ('🟢 NY' if nykz else '⚪ Outside')}")
        tg_send(txt)

    elif cmd == "/killzone":
        lkz,nykz = killzone(h)
        tg_send(f"<b>📡 Killzone</b> — {wib_fmt()}\n━━━━━━━━━━━━━━━━\n"
                f"🇬🇧 London: {'🟢 ACTIVE' if lkz else '⚪ Inactive'}\n"
                f"🇺🇸 NY: {'🟢 ACTIVE' if nykz else '⚪ Inactive'}\n"
                f"Session: {session(h)}")

    elif cmd == "/status":
        bridge = "🟢" if check_bridge() else "🔴"
        tg_send(f"<b>⚡ PhantomFX Status</b>\n━━━━━━━━━━━━━━━━\n"
                f"🤖 Bot: 🟢 Online\n📡 Bridge: {bridge}\n"
                f"⏰ {wib_fmt()} | {session(h)}\n━━━━━━━━━━━━━━━━\n"
                f"/price /analyze /phantomfx /data")

    elif cmd in ("/analyze","/signal","/phantomfx"):
        tg_send("🔍 PhantomFX analyzing XAUUSD... ~30s")
        price = fetch_price(); dxy = fetch_dxy()
        lkz,nykz = killzone(h)
        kz = "London" if lkz else ("NY" if nykz else "Outside")
        sig = ask_ai(price, dxy, session(h), kz, 0)
        if sig:
            tg_send(fmt_signal(sig, price, dxy, h))
        else:
            sr = basic_sr(price)
            dxy_str = f"{dxy:.2f}" if dxy else "N/A"
            bias_emoji = "🟢" if sr['bias'] == 'BULLISH' else "🔴"
            tg_send(f"<b>📊 PhantomFX Technical Analysis</b>\n━━━━━━━━━━━━━━━━\n"
                    f"💰 XAUUSD <b>${price:,.2f}</b> | DXY: {dxy_str}\n"
                    f"Session: {session(h)} | {wib_fmt()}\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"Bias: {bias_emoji} <b>{sr['bias']}</b>\n"
                    f"Pivot: <b>${sr['pivot']:,}</b>\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"R3: ${sr['r3']:,} | R2: ${sr['r2']:,} | R1: ${sr['r1']:,}\n"
                    f"━━━ PIVOT ━━━\n"
                    f"S1: ${sr['s1']:,} | S2: ${sr['s2']:,} | S3: ${sr['s3']:,}\n"
                    f"━━━━━━━━━━━━━━━━\n"
                    f"Nearest S: ${sr['nearest_support']:,} | Nearest R: ${sr['nearest_resistance']:,}\n"
                    f"<i>AI signal unavailable — pivot analysis</i>")


# ═══════════════════════════════════════════════════════════════
# AUTONOMOUS SIGNAL GENERATOR
# ═══════════════════════════════════════════════════════════════

SIGNAL_LOG_PATH = DATA_DIR / "signal_log.json"

def load_signal_log():
    try:
        if SIGNAL_LOG_PATH.exists():
            return json.loads(SIGNAL_LOG_PATH.read_text())
    except: pass
    today = wib_now().strftime("%Y-%m-%d")
    return {"date": today, "signals_sent": 0, "loss_count": 0, "last_signal_time": None, "signals": []}

def save_signal_log(log):
    SIGNAL_LOG_PATH.write_text(json.dumps(log, indent=2))

def is_trading_session(h=None):
    """Check if we're in an active trading session."""
    h = h if h is not None else wib_now().hour
    return (9 <= h < 17) or (19 <= h < 23)  # London or NY

def should_generate(log):
    """Check if we should generate a new signal."""
    now = wib_now()
    today = now.strftime("%Y-%m-%d")
    
    # Reset daily counters
    if log.get("date") != today:
        log = {"date": today, "signals_sent": 0, "loss_count": 0, "last_signal_time": None, "signals": []}
    
    # Circuit breaker
    if log["loss_count"] >= 3:
        return False, log
    
    # Max 5 signals per session
    if log["signals_sent"] >= 5:
        return False, log
    
    # Throttle: minimum 5 min between signals
    if log.get("last_signal_time"):
        try:
            last = datetime.fromisoformat(log["last_signal_time"])
            if (now - last).total_seconds() < 300:
                return False, log
        except: pass
    
    return True, log

def auto_analyze_loop():
    """Background loop: generate signals during trading sessions."""
    logger.info("🔄 Auto-signal loop started")
    
    while True:
        try:
            h = wib_now().hour
            
            if not is_trading_session(h):
                # Outside trading — sleep longer
                sleep_time = 120 if 0 <= h < 9 else 60
                time.sleep(sleep_time)
                continue
            
            # During trading session
            log = load_signal_log()
            should_gen, log = should_generate(log)
            
            if not should_gen:
                time.sleep(30)
                continue
            
            # Fetch price
            price = fetch_price()
            if not price:
                logger.warning("Auto-signal: price unavailable")
                time.sleep(60)
                continue
            
            dxy = fetch_dxy()
            lkz, nykz = killzone(h)
            kz = "London" if lkz else ("NY" if nykz else "Outside")
            
            logger.info(f"🔍 Auto-analyze: XAUUSD=${price:.1f} | {session(h)} | KZ={kz}")
            
            sig = ask_ai(price, dxy, session(h), kz, log["loss_count"])
            
            if not sig:
                time.sleep(60)
                continue
            
            action = sig.get("action", "HOLD")
            ensemble = sig.get("ensemble", "")
            confidence = sig.get("confidence", 0)
            
            # Push signal when:
            # - Opus solo or ensemble agree
            # - Action is BUY or SELL
            # - Confidence >= 0.65
            # - SKC score >= 7.0 (YELLOW zone minimum)
            skc = sig.get("skc_score", {})
            skc_total = skc.get("total", 0) if isinstance(skc, dict) else 0
            
            if ensemble in ("agree", "opus_solo", "single") and action in ("BUY", "SELL") and confidence >= 0.65:
                logger.info(f"🚀 AUTO SIGNAL: {action} | SKC={skc_total:.1f}/10 | conf={confidence:.0%} | {sig.get('reasoning','')[:60]}")
                
                # Format and send
                text = fmt_signal(sig, price, dxy, h) + f"\n<i>[AUTO] Generated during {session(h)} session</i>"
                tg_send(text)
                
                # Update log
                log["signals_sent"] += 1
                log["last_signal_time"] = wib_now().isoformat()
                log["signals"].append({
                    "time": wib_now().isoformat(),
                    "action": action,
                    "confidence": confidence,
                    "skc_score": skc_total,
                    "entry": sig.get("entry"),
                    "price_at_signal": price,
                    "session": session(h),
                    "combat_style": sig.get("combat_style"),
                })
                save_signal_log(log)
                
                # Wait longer after sending a signal
                time.sleep(300)  # 5 min cooldown
            elif ensemble == "disagree":
                logger.info(f"   Split → skip (models disagree)")
                time.sleep(90)
            else:
                grade = sig.get('grade','?')
                skc_str = f"SKC={skc_total:.1f}" if skc_total > 0 else ""
                reason = sig.get('reasoning','')[:50]
                logger.info(f"   {action} | Grade:{grade} | {skc_str} | {reason}")
                time.sleep(60)
                
        except Exception as e:
            logger.error(f"Auto-loop error: {e}")
            time.sleep(60)


def main():
    if not TOKEN:
        logger.error("PHANTOMFX_TELEGRAM_BOT_TOKEN not set!"); sys.exit(1)

    state = load_state()
    last_update_id = state.get("last_update_id", 0)
    consecutive_errors = 0

    logger.info(f"🤖 PhantomFX Bot starting — @berkahkaryaforexbotbot")
    logger.info(f"   Chat: {CHAT_ID} | Offset: {last_update_id} | Time: {wib_fmt()}")
        # Start autonomous signal generator in background thread
    auto_thread = threading.Thread(target=auto_analyze_loop, daemon=True, name="auto-signal")
    auto_thread.start()
    logger.info("   Auto-signal generator: ENABLED (London + NY sessions)")
    while True:
        try:
            url = f"https://api.telegram.org/bot{TOKEN}/getUpdates?offset={last_update_id+1}&timeout=30"
            resp = json.loads(urllib.request.urlopen(url, timeout=35).read())

            if not resp.get("ok"):
                consecutive_errors += 1
                logger.error(f"TG API fail: {resp}")
                time.sleep(min(consecutive_errors*2, 30))
                continue

            consecutive_errors = 0
            updates = resp.get("result", [])

            for upd in updates:
                last_update_id = upd["update_id"]
                msg = upd.get("message", {})
                text = (msg.get("text") or "").strip()
                chat = msg.get("chat", {})
                chat_id = str(chat.get("id", ""))

                # Accept all chats (DM + groups)
                pass

                cmd = text.split()[0].lower().split("@")[0] if text else ""
                logger.info(f"📨 [{chat_id}] {cmd} — {text[:40]}")

                try:
                    handle_command(cmd, text, chat_id)
                except Exception as e:
                    logger.error(f"Handler error for {cmd}: {e}")

            if updates:
                save_state({"last_update_id": last_update_id})

        except Exception as e:
            consecutive_errors += 1
            logger.error(f"Poll error: {e}")
            time.sleep(min(consecutive_errors*2, 30))

if __name__ == "__main__":
    main()
