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
    sources = [
        ("gold-api", f"https://api.gold-api.com/price/{pair.upper() if pair != 'gold' else 'XAU'}",
         lambda r: float(r.get("price")) if r.get("price") else None),
        ("metals.live", f"https://api.metals.live/v1/spot/{pair}",
         lambda r: float(r["price"]) if r.get("price") else None),
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

def tg_send(text):
    if not TOKEN: return False
    try:
        payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
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

SYSTEM_PROMPT = """You are PhantomFX institutional XAUUSD trader.
Output ONLY this exact JSON (no markdown, no extra text):
{"action":"BUY|SELL|HOLD","entry":0.0,"sl":0.0,"tp":0.0,"confidence":0.0,"grade":"A|B|C|D","combat_style":"SNIPER|COMMANDO|CRUSADER|LIQUIDITY_HUNTER|HOLD","rr_ratio":0.0,"reasoning":"1 sentence Indonesian","bias":"BULLISH|BEARISH|NEUTRAL","key_levels":{"support":0.0,"resistance":0.0}}
R:RR>=1:2. Uncertain=HOLD."""

def _call_claude(prompt):
    """Try Claude API. Returns parsed signal or None."""
    if not CLAUDE_KEY:
        return None
    try:
        data = json.dumps({
            "model":"claude-sonnet-4-20250514",
            "max_tokens":600,"temperature":0.3,
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
        m = re.search(r'\{[^{}]*"action"[^}]*\}', content)
        if m: return json.loads(m.group(0))
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
        m = re.search(r'\{[^{}]*"action"[^}]*\}', content)
        if m: return json.loads(m.group(0))
    except Exception as e:
        logger.warning(f"DeepSeek error: {e}")
    return None

def ask_ai_ensemble(price, dxy, sess, kz_str, loss_count):
    """Multi-model ensemble: Claude + DeepSeek debate for confidence."""
    prompt = f"XAUUSD=${price:.1f} DXY={dxy or 'N/A'} Session={sess} KZ={kz_str} Loss={loss_count}/3. 7TF SMC JSON only."
    
    signals = []
    
    # Collect signals from all available models
    claude_sig = _call_claude(prompt)
    if claude_sig:
        claude_sig["_model"] = "Claude"
        signals.append(claude_sig)
    
    deepseek_sig = _call_deepseek(prompt)
    if deepseek_sig:
        deepseek_sig["_model"] = "DeepSeek"
        signals.append(deepseek_sig)
    
    if not signals:
        return None
    
    if len(signals) == 1:
        # Single model — use as-is
        sig = signals[0]
        sig["ensemble"] = "single"
        sig["voters"] = 1
        return sig
    
    # Multi-model ensemble
    s1, s2 = signals[0], signals[1]
    actions = [s.get("action") for s in signals]
    biases = [s.get("bias") for s in signals]
    
    # Determine agreement
    agree_action = actions[0] == actions[1]
    agree_bias = biases[0] == biases[1] if biases[0] and biases[1] else False
    
    if agree_action:
        # Both agree — boost confidence
        avg_conf = (s1.get("confidence", 0.5) + s2.get("confidence", 0.5)) / 2
        ensemble_conf = min(avg_conf * 1.1, 0.95)  # +10% bonus for agreement
        
        result = dict(s1)  # Use Claude's structure
        result["confidence"] = round(ensemble_conf, 2)
        result["reasoning"] = f"[Claude+DeepSeek agree] {s1.get('reasoning','')[:120]}"
        result["ensemble"] = "agree"
        result["voters"] = 2
        result["grade"] = "A" if ensemble_conf >= 0.8 else ("B" if ensemble_conf >= 0.65 else "C")
        
        # Average key levels
        for key in ["entry","sl","tp"]:
            v1 = s1.get(key, 0) or 0
            v2 = s2.get(key, 0) or 0
            if v1 and v2:
                result[key] = round((v1 + v2) / 2, 2)
        
        kl1 = s1.get("key_levels", {})
        kl2 = s2.get("key_levels", {})
        if kl1 and kl2:
            result["key_levels"] = {
                "support": round(((kl1.get("support",0) or 0) + (kl2.get("support",0) or 0)) / 2, 2),
                "resistance": round(((kl1.get("resistance",0) or 0) + (kl2.get("resistance",0) or 0)) / 2, 2),
            }
        return result
    else:
        # Disagree → HOLD with reduced confidence
        return {
            "action": "HOLD",
            "entry": 0, "sl": 0, "tp": 0,
            "confidence": 0.3,
            "grade": "D",
            "combat_style": "HOLD",
            "rr_ratio": 0,
            "bias": "NEUTRAL",
            "key_levels": {},
            "reasoning": f"[DEBATE] Claude: {actions[0]} vs DeepSeek: {actions[1]}. No consensus → HOLD. {s1.get('reasoning','')[:80]}",
            "ensemble": "disagree",
            "voters": 2,
        }

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
    if a != "HOLD" and sig.get("entry"):
        text += (f"\nEntry: <b>${sig['entry']:.2f}</b>\n"
                 f"SL: <b>${sig['sl']:.2f}</b> | TP: <b>${sig['tp']:.2f}</b>\n"
                 f"R:R = 1:{sig.get('rr_ratio',0):.1f}\n")
    kl = sig.get("key_levels",{})
    if kl: text += f"S: ${kl.get('support',0):,} | R: ${kl.get('resistance',0):,}\n"
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
            
            # Only push when:
            # - Both models agree (ensemble="agree") 
            # - Action is BUY or SELL
            # - Confidence >= 0.65
            if ensemble == "agree" and action in ("BUY", "SELL") and confidence >= 0.65:
                logger.info(f"🚀 AUTO SIGNAL: {action} | conf={confidence:.0%} | {sig.get('reasoning','')[:60]}")
                
                # Format and send
                text = fmt_signal(sig, price, dxy, h) + "\n<i>[AUTO] Generated during {session(h)} session</i>"
                tg_send(text)
                
                # Update log
                log["signals_sent"] += 1
                log["last_signal_time"] = wib_now().isoformat()
                log["signals"].append({
                    "time": wib_now().isoformat(),
                    "action": action,
                    "confidence": confidence,
                    "entry": sig.get("entry"),
                    "price_at_signal": price,
                    "session": session(h),
                })
                save_signal_log(log)
                
                # Wait longer after sending a signal
                time.sleep(300)  # 5 min cooldown
            elif ensemble == "disagree":
                logger.info(f"   Split → skip (Claude vs DeepSeek disagree)")
                time.sleep(90)
            else:
                logger.info(f"   No consensus or HOLD → skip")
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
