#!/usr/bin/env python3
"""
PhantomFX Auto-Analyzer — Cron-driven XAUUSD Analysis
Polls AI → Bridge signal → EA execution → Telegram notification

Usage:
    python3 phantomfx_auto_analyzer.py
    python3 phantomfx_auto_analyzer.py --dry-run
Cron:
    */15 * * * * cd ~/projects/1ai-trade-bot && python3 scripts/phantomfx_auto_analyzer.py >> logs/phantomfx_analyzer.log 2>&1
"""

import argparse, json, logging, os, re, sys, time, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_DIR / "logs"; LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(LOG_DIR/"phantomfx_analyzer.log"), logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("phantomfx-analyzer")

def load_env():
    env = PROJECT_DIR/"strategies"/"phantomfx"/".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v = line.split("=",1); v = v.strip().strip('"').strip("'")
                if v and "***" not in v: os.environ.setdefault(k.strip(), v)

load_env()

OPENCLAW_URL = os.environ.get("OPENCLAW_GATEWAY_URL","http://localhost:20129")
BRIDGE_URL = os.environ.get("MT5_EA_WEBHOOK_URL","http://localhost:8765")
TELEGRAM_TOKEN = os.environ.get("PHANTOMFX_TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT_ID = os.environ.get("PHANTOMFX_TELEGRAM_CHAT_ID","-1002928711742")
STATE_FILE = PROJECT_DIR/"data"/"phantomfx"/"state.json"
WIB = timezone(timedelta(hours=7))

def wib_now(): return datetime.now(WIB)
def session(hour):
    if 9<=hour<17: return "London"
    if 17<=hour<19: return "Overlap"
    if 19<=hour<23: return "New York"
    return "Asian"

def load_state():
    if STATE_FILE.exists():
        s = json.loads(STATE_FILE.read_text())
        today = wib_now().strftime("%Y-%m-%d")
        if s.get("date") != today:
            s["loss_count_today"] = 0; s["last_trade"] = None; s["date"] = today
            STATE_FILE.parent.mkdir(parents=True,exist_ok=True); STATE_FILE.write_text(json.dumps(s,indent=2))
        return s
    return {"loss_count_today":0,"last_trade":None,"date":wib_now().strftime("%Y-%m-%d")}

def save_state(s):
    s["date"] = wib_now().strftime("%Y-%m-%d")
    STATE_FILE.parent.mkdir(parents=True,exist_ok=True)
    STATE_FILE.write_text(json.dumps(s,indent=2))

def send_telegram(text):
    if not TELEGRAM_TOKEN: return False
    try:
        data = json.dumps({"chat_id":TELEGRAM_CHAT_ID,"text":text,"parse_mode":"Markdown","disable_web_page_preview":True}).encode()
        r = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",data=data,
            headers={"Content-Type":"application/json"}),timeout=10).read())
        if r.get("ok"): logger.info("Telegram OK"); return True
        logger.error(f"Telegram fail: {r}"); return False
    except Exception as e: logger.error(f"Telegram err: {e}"); return False

def post_to_bridge(signal):
    try:
        data = json.dumps(signal).encode()
        r = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"{BRIDGE_URL}/signal",data=data,
            headers={"Content-Type":"application/json"}),timeout=10).read())
        logger.info(f"Bridge OK: {r}"); return True
    except Exception as e: logger.error(f"Bridge err: {e}"); return False

def fetch_price():
    for url in ["https://api.metals.live/v1/spot/gold"]:
        try:
            r = json.loads(urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"PhantomFX/4.1"}),timeout=8).read())
            p = r.get("price"); 
            if p: return {"price":float(p)}
        except: continue
    return {"price":2650.0}

def ask_ai(system_prompt, user_prompt, max_tokens=4000):
    try:
        data = json.dumps({"model":"gweb/gemini-2.5-flash","messages":[
            {"role":"system","content":system_prompt},
            {"role":"user","content":user_prompt}],
            "max_tokens":max_tokens,"temperature":0.3,"stream":False}).encode()
        headers = {"Content-Type":"application/json","User-Agent":"PhantomFX/4.1"}
        resp = urllib.request.urlopen(urllib.request.Request(
            f"{OPENCLAW_URL}/v1/chat/completions",data=data,headers=headers),timeout=120)
        # Handle SSE streaming response
        raw = resp.read().decode()
        content_parts = []
        for line in raw.split('\n'):
            if line.startswith('data: '):
                line = line[6:].strip()
                if line and line != '[DONE]':
                    try:
                        chunk = json.loads(line)
                        delta = chunk.get('choices',[{}])[0].get('delta',{})
                        c = delta.get('content','')
                        if c: content_parts.append(c)
                    except: pass
        content = ''.join(content_parts)
        logger.info(f"AI raw tokens estimate: {len(raw)} bytes → {len(content)} chars content")
        return content if content else None
    except Exception as e: logger.error(f"AI err: {e}"); return None

def parse_response(content):
    result = {"parsed":{},"signal":None,"killzone":None,"circuit":None,"error":None}
    m = re.search(r'```json\s*\n([\s\S]*?)\n```', content)
    if not m: m = re.search(r'\{[^{}]*"system"\s*:\s*"PhantomFX[^}]*\}', content, re.DOTALL)
    try:
        if m:
            txt = m.group(1) if m.lastindex else m.group(0)
            result["parsed"] = json.loads(txt)
    except Exception as e: result["error"] = str(e); logger.error(f"JSON parse: {e}")
    for name,key in [("signal","SIGNAL"),("killzone","KILLZONE"),("circuit","CIRCUIT")]:
        m2 = re.search(rf'---TELEGRAM_{key}_START---\n([\s\S]*?)\n---TELEGRAM_{key}_END---', content)
        if m2: result[name] = m2.group(1)
    return result

def run_cycle(args):
    logger.info("=" * 50)
    now = wib_now(); h = now.hour
    logger.info(f"⚡ PhantomFX Cycle — {now.strftime('%H:%M')} WIB | {session(h)}")
    state = load_state()

    if state["loss_count_today"] >= 3:
        logger.warning(f"CB: {state['loss_count_today']}/3"); send_telegram("🚨 *CB Active* — Trading halted"); return

    price = fetch_price()
    logger.info(f"XAUUSD: ${price['price']}")

    # Simplified PhantomFX prompt for auto-analysis
    sys_prompt = """You are PhantomFX, an institutional XAUUSD trading AI. Output ONLY valid JSON with these fields:
- action: BUY, SELL, or HOLD
- entry: entry price (0 if HOLD)
- sl: stop loss (0 if HOLD)
- tp: take profit (0 if HOLD)  
- combat_style: SNIPER, COMMANDO, CRUSADER, LIQUIDITY_HUNTER, or HOLD
- confidence: 0.0 to 1.0
- grade: A, B, C, or D
- reasoning: 2-3 sentence analysis
- mt5_webhook: {{"ready": true/false, "symbol":"XAUUSD", "type":"OP_BUY/OP_SELL/SKIP", "price":0, "sl":0, "tp":0, "risk_percent":1.0, "comment":""}}
- notify_telegram: true/false

Rules: R:R minimum 1:2. When uncertain, HOLD. Never force a trade."""

    kz_l = 9<=h<11; kz_ny = 20<=h<22
    kz_str = ", ".join(filter(None,[kz_l and "London 🟢",kz_ny and "NY 🟢"])) or "Outside ⚪"

    user_prompt = f"""━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 PhantomFX | Cycle: {now.strftime('%Y%m%dT%H%M%S')}
💰 Session: {session(h)} | Time: {now.strftime('%H:%M')} WIB
📡 Killzone: {kz_str}
🔴 Loss: {state['loss_count_today']}/3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[⚠️ CB CHECK FIRST] loss≥3 → HOLD. <3 → continue.

📊 XAUUSD: ${price['price']}
📡 London({'🟢' if kz_l else '⚪'}) NY({'🟢' if kz_ny else '⚪'}) | Session: {session(h)}

Analyze XAUUSD 7-TF. Apply SMC. Calculate SKC. TRIPLE OUTPUT format required."""

    if args.dry_run:
        logger.info("DRY RUN — skip AI"); return

    start = time.time()
    content = ask_ai(sys_prompt, user_prompt, args.max_tokens)
    if not content: return

    logger.info(f"AI done in {time.time()-start:.1f}s")
    result = parse_response(content)
    if result["error"]:
        logger.error(f"Parse fail: {result['error']}")
        (LOG_DIR/f"debug_{now.strftime('%Y%m%d_%H%M%S')}.txt").write_text(content)
        return

    p = result["parsed"]; action = p.get("action","HOLD")
    logger.info(f"→ {action} | {p.get('combat_style')} | Grade:{p.get('grade')} | "
                f"Conf:{p.get('confidence')} | SKC:{p.get('skc_score',{}).get('total','?')}")

    # Telegram
    for key in ["circuit","killzone","signal"]:
        if result[key]: send_telegram(result[key])

    # Bridge
    mt5 = p.get("mt5_webhook",{})
    if action in ("BUY","SELL") and mt5.get("ready"):
        sig = {"signal_id":f"pfx_{now.strftime('%Y%m%dT%H%M%S')}","symbol":"XAUUSD",
               "action":action,"entry":mt5.get("price",p.get("entry",0)),
               "sl":mt5.get("sl",p.get("sl",0)),"tp":mt5.get("tp",p.get("tp",0)),
               "risk_percent":mt5.get("risk_percent",1.0),
               "comment":mt5.get("comment",f"PhantomFX_{p.get('combat_style','AUTO')}")}
        post_to_bridge(sig)

    state["last_cycle"] = now.isoformat(); save_state(state)
    logger.info(f"Done — {time.time()-start:.0f}s")

def main():
    p = argparse.ArgumentParser(); p.add_argument("--dry-run","-n",action="store_true")
    p.add_argument("--max-tokens",type=int,default=8000)
    p.add_argument("--quiet","-q",action="store_true"); args = p.parse_args()
    try: run_cycle(args)
    except Exception as e: logger.exception(f"Fatal: {e}"); sys.exit(1)

if __name__=="__main__": main()
