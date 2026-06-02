//+------------------------------------------------------------------+
//|                                          PhantomFX_Webhook_EA.mq5 |
//|                        PhantomFX | GENESIS AI Trader v4.0         |
//|                        Polling EA — Fetches signals via WebRequest|
//+------------------------------------------------------------------+
#property copyright "PhantomFX - BerkahKarya"
#property link      "https://t.me/berkahkaryaforexbotbot"
#property version   "4.1"
#property description "PhantomFX EA v4.1 — Polls signal bridge for trade signals"

//+------------------------------------------------------------------+
//| INPUT PARAMETERS                                                  |
//+------------------------------------------------------------------+
input group "=== Signal Bridge Server ==="
input string   SignalBridgeURL   = "http://localhost:8765"; // Signal Bridge URL
input int      PollIntervalSec   = 3;                        // Poll interval (seconds)

input group "=== Risk Management ==="
input double   DefaultRiskPercent = 1.0;       // Default Risk % per trade
input double   MaxRiskPercent     = 2.0;       // Max Risk % per trade
input int      MagicNumber        = 234000;    // EA Magic Number

input group "=== Session Filter ==="
input bool     FilterSessions     = true;      // Filter by trading sessions
input bool     TradeAsian         = false;     // Allow Asian session
input bool     TradeLondon        = true;      // Allow London session
input bool     TradeNY            = true;      // Allow NY session

input group "=== Circuit Breaker ==="
input int      MaxDailyLosses     = 3;         // Max consecutive losses
input double   MaxDailyDrawdown   = 5.0;       // Max daily DD % before halt

//+------------------------------------------------------------------+
//| GLOBAL VARIABLES                                                  |
//+------------------------------------------------------------------+
datetime g_lastPollTime = 0;
datetime g_lastTradeTime = 0;
int g_lossCountToday = 0;
double g_startingBalance = 0;
double g_dailyPnL = 0;
string g_lastSignalId = "";    // Prevent duplicate execution
string g_statusText = "INIT";

//+------------------------------------------------------------------+
//| Expert initialization                                             |
//+------------------------------------------------------------------+
int OnInit() {
   g_startingBalance = AccountInfoDouble(ACCOUNT_BALANCE);
   g_lossCountToday = LoadDailyLossCount();
   
   Print("╔══════════════════════════════════════════════╗");
   Print("║  PhantomFX EA v4.1 — INITIALIZED             ║");
   Print("╚══════════════════════════════════════════════╝");
   PrintFormat("Balance: %.2f | LossCount: %d | Magic: %d", 
               g_startingBalance, g_lossCountToday, MagicNumber);
   PrintFormat("Bridge: %s | Poll: %ds", SignalBridgeURL, PollIntervalSec);
   
   // Verify WebRequest is allowed for the bridge URL
   Print("⚠️  PASTIKAN WebRequest diizinkan: Tools → Options → Expert Advisors → Allow WebRequest for: ", SignalBridgeURL);
   
   EventSetTimer(PollIntervalSec);
   g_statusText = "LISTENING";
   
   return INIT_SUCCEEDED;
}

//+------------------------------------------------------------------+
//| Expert deinitialization                                           |
//+------------------------------------------------------------------+
void OnDeinit(const int reason) {
   SaveDailyLossCount();
   EventKillTimer();
   
   PrintFormat("PhantomFX EA stopped | Reason: %d | Daily P&L: %.2f | Losses: %d", 
               reason, g_dailyPnL, g_lossCountToday);
}

//+------------------------------------------------------------------+
//| TIMER — Poll signal bridge                                        |
//+------------------------------------------------------------------+
void OnTimer() {
   // Reset at midnight
   MqlDateTime dt;
   TimeCurrent(dt);
   if(dt.hour == 0 && dt.min == 0 && dt.sec < 10) {
      g_lossCountToday = 0;
      g_startingBalance = AccountInfoDouble(ACCOUNT_BALANCE);
      SaveDailyLossCount();
   }
   
   // Poll signal bridge
   PollSignalBridge();
   
   // Update chart comment
   UpdateComment();
}

//+------------------------------------------------------------------+
//| POLL SIGNAL BRIDGE                                                |
//+------------------------------------------------------------------+
void PollSignalBridge() {
   // Don't poll too frequently
   if(TimeCurrent() - g_lastPollTime < PollIntervalSec) return;
   g_lastPollTime = TimeCurrent();
   
   // Fetch pending signal via WebRequest
   string url = SignalBridgeURL + "/signal";
   char result[];
   string resultHeaders;
   char postData[];
   
   int res = WebRequest("GET", url, NULL, NULL, 2000, postData, 0, result, resultHeaders);
   
   if(res == -1) {
      // Only log errors occasionally to avoid spam
      static int errorCount = 0;
      errorCount++;
      if(errorCount % 20 == 0) {
         PrintFormat("[WARN] WebRequest failed (%d times): %d", errorCount, GetLastError());
      }
      g_statusText = "BRIDGE_OFFLINE";
      return;
   }
   
   if(res != 200) {
      g_statusText = "BRIDGE_ERR";
      return;
   }
   
   string response = CharArrayToString(result, 0, ArraySize(result));
   StringTrimLeft(response);
   StringTrimRight(response);
   
   // Empty response = no signal
   if(response == "" || response == "{}" || response == "null") {
      g_statusText = "IDLE";
      return;
   }
   
   // Parse signal (simple key-value parsing for MQL5)
   string signalId = ExtractValue(response, "signal_id");
   string symbol = ExtractValue(response, "symbol");
   string action = ExtractValue(response, "action");
   double entry = StringToDouble(ExtractValue(response, "entry"));
   double sl = StringToDouble(ExtractValue(response, "sl"));
   double tp = StringToDouble(ExtractValue(response, "tp"));
   double risk = StringToDouble(ExtractValue(response, "risk_percent"));
   string comment = ExtractValue(response, "comment");
   
   // Validate
   if(symbol == "" || action == "") {
      g_statusText = "PARSE_ERR";
      return;
   }
   
   // Prevent duplicate execution
   if(signalId == g_lastSignalId && signalId != "") {
      return;
   }
   
   // Acknowledge signal (mark as received)
   AckSignal(signalId);
   g_lastSignalId = signalId;
   
   PrintFormat("[SIGNAL] %s | %s | %s | Entry:%.2f SL:%.2f TP:%.2f Risk:%.1f%%", 
               signalId, symbol, action, entry, sl, tp, risk);
   
   // Execute trade
   ExecuteSignal(symbol, action, entry, sl, tp, risk, comment);
}

//+------------------------------------------------------------------+
//| EXECUTE SIGNAL AS TRADE                                           |
//+------------------------------------------------------------------+
void ExecuteSignal(string symbol, string action, double entry, 
                   double sl, double tp, double risk, string comment) {
   
   // Circuit breaker check
   if(g_lossCountToday >= MaxDailyLosses) {
      Print("[CIRCUIT BREAKER] Max losses reached: ", g_lossCountToday, "/", MaxDailyLosses);
      g_statusText = "CB_ACTIVE";
      return;
   }
   
   // Drawdown check
   double equity = AccountInfoDouble(ACCOUNT_EQUITY);
   double dd = (g_startingBalance - equity) / g_startingBalance * 100;
   if(dd > MaxDailyDrawdown) {
      Print("[CIRCUIT BREAKER] Max DD: ", DoubleToString(dd, 1), "%");
      g_statusText = "DD_LIMIT";
      return;
   }
   
   // Session filter
   if(FilterSessions && !IsValidSession()) {
      Print("[SESSION] Outside trading session");
      g_statusText = "OUTSIDE_SESSION";
      return;
   }
   
   // Skip/Hold
   if(action == "HOLD" || action == "SKIP") {
      Print("[HOLD] Signal is HOLD/SKIP");
      g_statusText = "HOLD";
      return;
   }
   
   // Validate symbol
   double bid = SymbolInfoDouble(symbol, SYMBOL_BID);
   double ask = SymbolInfoDouble(symbol, SYMBOL_ASK);
   if(bid == 0 || ask == 0) {
      Print("[ERROR] Symbol not found: ", symbol);
      g_statusText = "BAD_SYMBOL";
      return;
   }
   
   // Default risk
   if(risk <= 0) risk = DefaultRiskPercent;
   if(risk > MaxRiskPercent) risk = MaxRiskPercent;
   
   // Calculate lot size
   double lot = CalculateLotSize(symbol, sl, entry, risk);
   if(lot <= 0) {
      Print("[ERROR] Invalid lot size");
      g_statusText = "LOT_ERR";
      return;
   }
   
   // Prepare trade request
   MqlTradeRequest req = {};
   MqlTradeResult res = {};
   
   req.action = TRADE_ACTION_DEAL;
   req.symbol = symbol;
   req.volume = lot;
   req.magic = MagicNumber;
   req.comment = comment;
   req.type_filling = ORDER_FILLING_IOC;
   
   if(action == "BUY") {
      req.type = ORDER_TYPE_BUY;
      req.price = ask;
   } else if(action == "SELL") {
      req.type = ORDER_TYPE_SELL;
      req.price = bid;
   } else {
      Print("[ERROR] Unknown action: ", action);
      return;
   }
   
   // Set SL/TP
   if(sl > 0) req.sl = sl;
   if(tp > 0) req.tp = tp;
   
   // Execute
   if(!OrderSend(req, res)) {
      Print("[ERROR] OrderSend failed: ", res.comment, " | Retcode: ", res.retcode);
      g_statusText = "ORDER_FAIL";
      return;
   }
   
   if(res.retcode == TRADE_RETCODE_DONE || res.retcode == TRADE_RETCODE_DONE_PARTIAL) {
      PrintFormat("[EXECUTED] Ticket:%d | %s %s | Lot:%.2f Price:%.2f SL:%.2f TP:%.2f", 
                  res.order, symbol, action, lot, res.price, sl, tp);
      g_lastTradeTime = TimeCurrent();
      g_statusText = "TRADED";
   } else {
      Print("[ERROR] Trade failed: retcode=", res.retcode);
      g_statusText = "TRADE_FAIL";
   }
}

//+------------------------------------------------------------------+
//| ACKNOWLEDGE SIGNAL (mark as processed)                             |
//+------------------------------------------------------------------+
void AckSignal(string signalId) {
   if(signalId == "") return;
   
   string url = SignalBridgeURL + "/ack/" + signalId;
   char result[];
   string resultHeaders;
   char postData[];
   
   WebRequest("POST", url, NULL, NULL, 2000, postData, 0, result, resultHeaders);
}

//+------------------------------------------------------------------+
//| CALCULATE LOT SIZE                                                |
//+------------------------------------------------------------------+
double CalculateLotSize(string symbol, double sl, double entry, double riskPercent) {
   double balance = AccountInfoDouble(ACCOUNT_BALANCE);
   double riskAmount = balance * (riskPercent / 100.0);
   
   double tickValue = SymbolInfoDouble(symbol, SYMBOL_TRADE_TICK_VALUE);
   double tickSize = SymbolInfoDouble(symbol, SYMBOL_TRADE_TICK_SIZE);
   double point = SymbolInfoDouble(symbol, SYMBOL_POINT);
   double lotStep = SymbolInfoDouble(symbol, SYMBOL_VOLUME_STEP);
   double lotMin = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MIN);
   double lotMax = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MAX);
   
   if(tickValue <= 0 || tickSize <= 0 || point <= 0) return lotMin;
   
   double slPoints;
   if(sl > 0 && entry > 0) {
      slPoints = MathAbs(entry - sl) / point;
   } else {
      slPoints = 300; // Default 30 pips
   }
   
   double lotSize = riskAmount / (slPoints * tickValue * (point / tickSize) * 10);
   
   lotSize = MathRound(lotSize / lotStep) * lotStep;
   lotSize = MathMax(lotMin, MathMin(lotMax, lotSize));
   
   return NormalizeDouble(lotSize, 2);
}

//+------------------------------------------------------------------+
//| SESSION FILTER                                                    |
//+------------------------------------------------------------------+
bool IsValidSession() {
   MqlDateTime dt;
   TimeCurrent(dt);
   int hour = dt.hour; // Server time (usually UTC)
   
   if(hour >= 8 && hour < 17 && TradeLondon) return true;
   if(hour >= 13 && hour < 22 && TradeNY) return true;
   if((hour >= 23 || hour < 8) && TradeAsian) return true;
   
   return false;
}

//+------------------------------------------------------------------+
//| SIMPLE JSON VALUE EXTRACTOR                                       |
//+------------------------------------------------------------------+
string ExtractValue(string json, string key) {
   string search = "\"" + key + "\"";
   int pos = StringFind(json, search);
   if(pos < 0) return "";
   
   int colon = StringFind(json, ":", pos);
   if(colon < 0) return "";
   
   int start = colon + 1;
   while(start < StringLen(json)) {
      ushort c = StringGetCharacter(json, start);
      if(c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
      start++;
   }
   
   if(start >= StringLen(json)) return "";
   
   ushort first = StringGetCharacter(json, start);
   
   if(first == '"') {
      start++;
      int end = StringFind(json, "\"", start);
      if(end < 0) return "";
      return StringSubstr(json, start, end - start);
   } else {
      int end = start;
      while(end < StringLen(json)) {
         ushort c = StringGetCharacter(json, end);
         if(c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r') break;
         end++;
      }
      string val = StringSubstr(json, start, end - start);
      StringTrimLeft(val);
      StringTrimRight(val);
      return val;
   }
}

//+------------------------------------------------------------------+
//| DAILY LOSS COUNT                                                  |
//+------------------------------------------------------------------+
int LoadDailyLossCount() {
   string gvName = "PFX_Loss_" + IntegerToString(DayOfYear());
   if(GlobalVariableCheck(gvName)) {
      return (int)GlobalVariableGet(gvName);
   }
   return 0;
}

void SaveDailyLossCount() {
   GlobalVariableSet("PFX_Loss_" + IntegerToString(DayOfYear()), g_lossCountToday);
}

int DayOfYear() {
   MqlDateTime dt;
   TimeCurrent(dt);
   return dt.day_of_year;
}

//+------------------------------------------------------------------+
//| ON TRADE EVENT                                                    |
//+------------------------------------------------------------------+
void OnTrade() {
   HistorySelect(TimeCurrent() - 86400, TimeCurrent());
   int total = HistoryDealsTotal();
   
   for(int i = total - 1; i >= MathMax(0, total - 5); i--) {
      ulong ticket = HistoryDealGetTicket(i);
      if(ticket > 0) {
         if(HistoryDealGetInteger(ticket, DEAL_MAGIC) == MagicNumber) {
            if(HistoryDealGetInteger(ticket, DEAL_ENTRY) == DEAL_ENTRY_OUT) {
               double profit = HistoryDealGetDouble(ticket, DEAL_PROFIT);
               g_dailyPnL += profit;
               
               if(profit < 0) {
                  g_lossCountToday++;
               } else {
                  g_lossCountToday = 0;
               }
               SaveDailyLossCount();
            }
         }
      }
   }
}

//+------------------------------------------------------------------+
//| CHART COMMENT                                                     |
//+------------------------------------------------------------------+
void UpdateComment() {
   double equity = AccountInfoDouble(ACCOUNT_EQUITY);
   double dd = g_startingBalance > 0 ? (g_startingBalance - equity) / g_startingBalance * 100 : 0;
   
   string status;
   if(g_statusText == "LISTENING" || g_statusText == "IDLE") 
      status = "🟢 " + g_statusText;
   else if(g_statusText == "TRADED")
      status = "🔵 " + g_statusText;
   else if(g_statusText == "HOLD")
      status = "🟡 " + g_statusText;
   else
      status = "🔴 " + g_statusText;
   
   Comment(
      "⚡ PhantomFX EA v4.1",
      "━━━━━━━━━━━━━━━━━━━━",
      "Status: ", status,
      "Bridge: ", SignalBridgeURL,
      "Poll: ", PollIntervalSec, "s",
      "━━━━━━━━━━━━━━━━━━━━",
      "Balance: ", DoubleToString(AccountInfoDouble(ACCOUNT_BALANCE), 2),
      "Equity: ", DoubleToString(equity, 2),
      "Losses: ", g_lossCountToday, "/", MaxDailyLosses,
      "Daily P&L: ", DoubleToString(g_dailyPnL, 2),
      "DD: ", DoubleToString(dd, 1), "%",
      "━━━━━━━━━━━━━━━━━━━━",
      "Last: ", TimeToString(g_lastTradeTime)
   );
}

//+------------------------------------------------------------------+
