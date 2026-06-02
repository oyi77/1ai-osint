//+------------------------------------------------------------------+
//|                                        PhantomFX_Webhook_EA.mq5   |
//|                        PhantomFX | GENESIS AI Trader v4.0         |
//|                        Webhook Receiver for MT5 Auto-Trade        |
//+------------------------------------------------------------------+
#property copyright "PhantomFX - BerkahKarya"
#property link      "https://t.me/berkahkaryaforexbotbot"
#property version   "4.0"
#property description "PhantomFX Webhook EA — Receives trade signals via HTTP POST"
#property description "Usage: Set webhook URL in PhantomFX Connector to MT5"

//+------------------------------------------------------------------+
//| INPUT PARAMETERS                                                  |
//+------------------------------------------------------------------+
input group "=== Webhook Server Settings ==="
input int      WebhookPort       = 8765;        // Webhook Server Port
input string   WebhookToken      = "phantomfx"; // Auth Token for Security
input bool     EnableSSL         = false;       // Enable SSL (requires certificate)

input group "=== Risk Management ==="
input double   DefaultRiskPercent = 1.0;        // Default Risk % per trade
input double   MaxRiskPercent     = 2.0;        // Maximum Risk % per trade
input double   MinRRRatio         = 1.5;        // Minimum R:R Ratio
input int      MagicNumber        = 234000;     // EA Magic Number

input group "=== Session Filter ==="
input bool     FilterSessions     = true;       // Filter by trading sessions
input bool     TradeAsian         = false;      // Allow Asian session trades
input bool     TradeLondon        = true;       // Allow London session trades
input bool     TradeNY            = true;       // Allow NY session trades

input group "=== Circuit Breaker ==="
input int      MaxDailyLosses     = 3;          // Max consecutive losses per day
input double   MaxDailyDrawdown   = 5.0;        // Max daily drawdown % before halt

//+------------------------------------------------------------------+
//| GLOBAL VARIABLES                                                  |
//+------------------------------------------------------------------+
int g_webhookSocket = INVALID_HANDLE;
bool g_webhookRunning = false;
datetime g_lastTradeTime = 0;
int g_lossCountToday = 0;
double g_startingBalance = 0;
double g_dailyPnL = 0;

// Trade tracking
struct TradeRecord {
   datetime open_time;
   ulong    ticket;
   string   symbol;
   string   action;
   double   entry_price;
   double   sl;
   double   tp;
   double   risk_percent;
   string   combat_style;
   string   grade;
   string   comment;
};
TradeRecord g_lastTrades[10];
int g_tradeCount = 0;

//+------------------------------------------------------------------+
//| Expert initialization function                                     |
//+------------------------------------------------------------------+
int OnInit() {
   Print("╔══════════════════════════════════════════════╗");
   Print("║  PhantomFX Webhook EA v4.0 — INITIALIZED    ║");
   Print("╚══════════════════════════════════════════════╝");
   
   g_startingBalance = AccountInfoDouble(ACCOUNT_BALANCE);
   g_lossCountToday = LoadDailyLossCount();
   
   PrintFormat("Balance: %.2f | Loss Count Today: %d | Magic: %d", 
               g_startingBalance, g_lossCountToday, MagicNumber);
   PrintFormat("Webhook listening on port: %d | Token: %s", WebhookPort, WebhookToken);
   
   // Start webhook server
   if(!StartWebhookServer()) {
      Print("[ERROR] Failed to start webhook server!");
      return INIT_FAILED;
   }
   
   // Setup timer for housekeeping
   EventSetTimer(60); // Every 60 seconds
   
   return INIT_SUCCEEDED;
}

//+------------------------------------------------------------------+
//| Expert deinitialization function                                   |
//+------------------------------------------------------------------+
void OnDeinit(const int reason) {
   StopWebhookServer();
   SaveDailyLossCount();
   
   Print("╔══════════════════════════════════════════════╗");
   PrintFormat("║  PhantomFX EA STOPPED | Reason: %d          ║", reason);
   PrintFormat("║  Daily P&L: %.2f | Losses: %d               ║", g_dailyPnL, g_lossCountToday);
   Print("╚══════════════════════════════════════════════╝");
}

//+------------------------------------------------------------------+
//| Timer function — housekeeping                                     |
//+------------------------------------------------------------------+
void OnTimer() {
   // Reset loss count at midnight
   MqlDateTime dt;
   TimeCurrent(dt);
   if(dt.hour == 0 && dt.min == 0) {
      g_lossCountToday = 0;
      g_startingBalance = AccountInfoDouble(ACCOUNT_BALANCE);
      SaveDailyLossCount();
   }
}

//+------------------------------------------------------------------+
//| START WEBHOOK SERVER                                              |
//+------------------------------------------------------------------+
bool StartWebhookServer() {
   g_webhookSocket = SocketCreate();
   if(g_webhookSocket == INVALID_HANDLE) {
      Print("[ERROR] SocketCreate failed: ", GetLastError());
      return false;
   }
   
   if(!SocketBind(g_webhookSocket, WebhookPort)) {
      Print("[ERROR] SocketBind failed on port ", WebhookPort, ": ", GetLastError());
      return false;
   }
   
   if(!SocketListen(g_webhookSocket, 5)) {
      Print("[ERROR] SocketListen failed: ", GetLastError());
      return false;
   }
   
   g_webhookRunning = true;
   Print("[OK] Webhook server started on port ", WebhookPort);
   return true;
}

//+------------------------------------------------------------------+
//| STOP WEBHOOK SERVER                                               |
//+------------------------------------------------------------------+
void StopWebhookServer() {
   g_webhookRunning = false;
   if(g_webhookSocket != INVALID_HANDLE) {
      SocketClose(g_webhookSocket);
      g_webhookSocket = INVALID_HANDLE;
   }
}

//+------------------------------------------------------------------+
//| EXPERT TICK — Main loop (checks for incoming webhooks)            |
//+------------------------------------------------------------------+
void OnTick() {
   if(!g_webhookRunning) return;
   
   // Check for incoming connections (non-blocking)
   uint timeout_ms = 100;
   int client = SocketAccept(g_webhookSocket, timeout_ms);
   
   if(client != INVALID_HANDLE) {
      // Read HTTP request
      string request = SocketReadHTTP(client, 5000);
      
      if(StringLen(request) > 0) {
         ProcessHTTPRequest(client, request);
      }
      
      SocketClose(client);
   }
}

//+------------------------------------------------------------------+
//| READ HTTP REQUEST FROM SOCKET                                     |
//+------------------------------------------------------------------+
string SocketReadHTTP(int socket, uint timeout_ms) {
   string data = "";
   uint start = GetTickCount();
   uchar buffer[];
   
   while(GetTickCount() - start < timeout_ms) {
      uint len = SocketIsReadable(socket);
      if(len > 0) {
         ArrayResize(buffer, (int)len);
         uint read = SocketRead(socket, buffer, len, timeout_ms);
         if(read > 0) {
            string chunk = CharArrayToString(buffer, 0, read);
            data += chunk;
            
            // Check if HTTP request is complete (\r\n\r\n)
            int headerEnd = StringFind(data, "\r\n\r\n");
            if(headerEnd > 0) {
               // Extract body if Content-Length header exists
               int clPos = StringFind(data, "Content-Length:");
               if(clPos >= 0) {
                  int clEnd = StringFind(data, "\r\n", clPos);
                  string clStr = StringSubstr(data, clPos + 15, clEnd - clPos - 15);
                  StringTrimLeft(clStr);
                  StringTrimRight(clStr);
                  int contentLength = (int)StringToInteger(clStr);
                  
                  int bodyStart = headerEnd + 4;
                  if(StringLen(data) - bodyStart >= contentLength) {
                     break; // Full request received
                  }
               } else {
                  break; // No body, request complete
               }
            }
         }
      }
      Sleep(5);
   }
   
   return data;
}

//+------------------------------------------------------------------+
//| PROCESS HTTP REQUEST                                              |
//+------------------------------------------------------------------+
void ProcessHTTPRequest(int client, string request) {
   // Extract JSON body from HTTP request
   int headerEnd = StringFind(request, "\r\n\r\n");
   string body = "";
   if(headerEnd > 0) {
      body = StringSubstr(request, headerEnd + 4);
   }
   
   // Check authorization
   string authHeader = ExtractHeader(request, "Authorization:");
   if(authHeader != "" && StringFind(authHeader, "Bearer " + WebhookToken) < 0) {
      SendHTTPResponse(client, 401, "{\"error\":\"Unauthorized\"}");
      return;
   }
   
   if(body == "") {
      SendHTTPResponse(client, 400, "{\"error\":\"Empty body\"}");
      return;
   }
   
   Print("[WEBHOOK] Received: ", body);
   
   // Parse and execute trade
   bool success = ExecuteFromJSON(body);
   
   string response = success ? 
      "{\"status\":\"executed\",\"timestamp\":" + IntegerToString(TimeCurrent()) + "}" :
      "{\"status\":\"failed\",\"error\":\"Check MT5 logs\"}";
   
   SendHTTPResponse(client, success ? 200 : 500, response);
}

//+------------------------------------------------------------------+
//| SEND HTTP RESPONSE                                                |
//+------------------------------------------------------------------+
void SendHTTPResponse(int socket, int statusCode, string body) {
   string statusText = (statusCode == 200) ? "OK" : 
                       (statusCode == 400) ? "Bad Request" :
                       (statusCode == 401) ? "Unauthorized" : "Error";
   
   string response = StringFormat(
      "HTTP/1.1 %d %s\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: %d\r\n"
      "Connection: close\r\n"
      "\r\n"
      "%s",
      statusCode, statusText, StringLen(body), body
   );
   
   SocketSend(socket, StringToCharArray(response), 5000);
}

//+------------------------------------------------------------------+
//| EXTRACT HTTP HEADER                                               |
//+------------------------------------------------------------------+
string ExtractHeader(string request, string headerName) {
   int pos = StringFind(request, headerName);
   if(pos < 0) return "";
   
   int valStart = pos + StringLen(headerName);
   int valEnd = StringFind(request, "\r\n", valStart);
   if(valEnd < 0) return "";
   
   string value = StringSubstr(request, valStart, valEnd - valStart);
   StringTrimLeft(value);
   StringTrimRight(value);
   return value;
}

//+------------------------------------------------------------------+
//| EXECUTE TRADE FROM JSON                                           |
//+------------------------------------------------------------------+
bool ExecuteFromJSON(string json) {
   // Manual JSON parsing (MT5 doesn't have native JSON parser)
   // Expected format: {"symbol":"XAUUSD","type":"OP_BUY","price":0,"sl":0,"tp":0,"risk_percent":1.0,"comment":"PhantomFX_..."}
   
   string symbol = GetJSONValue(json, "symbol");
   string type = GetJSONValue(json, "type");
   double price = StringToDouble(GetJSONValue(json, "price"));
   double sl = StringToDouble(GetJSONValue(json, "sl"));
   double tp = StringToDouble(GetJSONValue(json, "tp"));
   double riskPercent = StringToDouble(GetJSONValue(json, "risk_percent"));
   string comment = GetJSONValue(json, "comment");
   
   if(symbol == "" || type == "") {
      Print("[ERROR] Missing symbol or type in JSON");
      return false;
   }
   
   // Validate risk
   if(riskPercent <= 0) riskPercent = DefaultRiskPercent;
   if(riskPercent > MaxRiskPercent) riskPercent = MaxRiskPercent;
   
   // Circuit breaker check
   if(g_lossCountToday >= MaxDailyLosses) {
      Print("[CIRCUIT BREAKER] Max daily losses reached (", g_lossCountToday, "). Trade blocked.");
      Comment("🔴 CIRCUIT BREAKER ACTIVE | Losses: ", g_lossCountToday, "/", MaxDailyLosses);
      return false;
   }
   
   // Check daily drawdown
   double currentEquity = AccountInfoDouble(ACCOUNT_EQUITY);
   double dailyDD = (g_startingBalance - currentEquity) / g_startingBalance * 100;
   if(dailyDD > MaxDailyDrawdown) {
      Print("[CIRCUIT BREAKER] Max daily DD reached: ", dailyDD, "%");
      return false;
   }
   
   // Session filter
   if(FilterSessions && !IsValidSession()) {
      Print("[SESSION] Outside allowed trading session");
      return false;
   }
   
   // Validate symbol
   if(SymbolInfoDouble(symbol, SYMBOL_BID) == 0) {
      Print("[ERROR] Symbol not found: ", symbol);
      return false;
   }
   
   // Calculate position size based on risk
   double lotSize = CalculateLotSize(symbol, sl, price, riskPercent);
   if(lotSize <= 0) {
      Print("[ERROR] Invalid lot size calculation");
      return false;
   }
   
   // Prepare trade request
   MqlTradeRequest req = {};
   MqlTradeResult res = {};
   
   req.action = TRADE_ACTION_DEAL;
   req.symbol = symbol;
   req.volume = lotSize;
   req.magic = MagicNumber;
   req.comment = comment;
   req.type_filling = ORDER_FILLING_IOC;
   
   if(type == "OP_BUY") {
      req.type = ORDER_TYPE_BUY;
      req.price = SymbolInfoDouble(symbol, SYMBOL_ASK);
   } else if(type == "OP_SELL") {
      req.type = ORDER_TYPE_SELL;
      req.price = SymbolInfoDouble(symbol, SYMBOL_BID);
   } else if(type == "SKIP" || type == "HOLD") {
      Print("[HOLD] Signal is SKIP/HOLD — no trade placed");
      return true;
   } else {
      Print("[ERROR] Unknown order type: ", type);
      return false;
   }
   
   // Set SL/TP
   if(sl > 0) req.sl = sl;
   if(tp > 0) req.tp = tp;
   
   // Execute
   if(!OrderSend(req, res)) {
      Print("[ERROR] OrderSend failed: ", res.comment, " | Error: ", GetLastError());
      
      // Handle specific errors
      if(res.retcode == TRADE_RETCODE_REJECT || res.retcode == TRADE_RETCODE_ERROR) {
         return false;
      }
   }
   
   if(res.retcode == TRADE_RETCODE_DONE || res.retcode == TRADE_RETCODE_DONE_PARTIAL) {
      Print("[TRADE EXECUTED] Ticket: ", res.order, 
            " | ", symbol, " | ", type, 
            " | Lot: ", lotSize, 
            " | Price: ", res.price,
            " | SL: ", sl, " | TP: ", tp,
            " | Comment: ", comment);
      
      // Track trade
      TrackTrade(res.order, symbol, type, res.price, sl, tp, riskPercent, comment);
      g_lastTradeTime = TimeCurrent();
      
      return true;
   } else {
      Print("[ERROR] Trade failed: retcode=", res.retcode, " | ", res.comment);
      return false;
   }
}

//+------------------------------------------------------------------+
//| CALCULATE LOT SIZE BASED ON RISK %                                |
//+------------------------------------------------------------------+
double CalculateLotSize(string symbol, double sl, double entry, double riskPercent) {
   double balance = AccountInfoDouble(ACCOUNT_BALANCE);
   double riskAmount = balance * (riskPercent / 100.0);
   
   double tickValue = SymbolInfoDouble(symbol, SYMBOL_TRADE_TICK_VALUE);
   double tickSize = SymbolInfoDouble(symbol, SYMBOL_TRADE_TICK_SIZE);
   double point = SymbolInfoDouble(symbol, SYMBOL_POINT);
   
   if(tickValue <= 0 || tickSize <= 0) {
      Print("[ERROR] Cannot get symbol info for ", symbol);
      return 0.01; // Fallback to minimum
   }
   
   double slPoints;
   if(sl > 0 && entry > 0) {
      slPoints = MathAbs(entry - sl) / point;
   } else {
      // Default SL: 30 pips
      slPoints = 300;
   }
   
   double lotSize = riskAmount / (slPoints * tickValue * (point / tickSize) * 10);
   
   // Round to valid step
   double lotStep = SymbolInfoDouble(symbol, SYMBOL_VOLUME_STEP);
   double lotMin = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MIN);
   double lotMax = SymbolInfoDouble(symbol, SYMBOL_VOLUME_MAX);
   
   lotSize = MathRound(lotSize / lotStep) * lotStep;
   lotSize = MathMax(lotMin, MathMin(lotMax, lotSize));
   
   return NormalizeDouble(lotSize, 2);
}

//+------------------------------------------------------------------+
//| TRACK TRADE IN RECORDS                                            |
//+------------------------------------------------------------------+
void TrackTrade(ulong ticket, string symbol, string action, double entry,
                double sl, double tp, double risk, string comment) {
   g_tradeCount++;
   
   // Shift array
   for(int i = 9; i > 0; i--) {
      g_lastTrades[i] = g_lastTrades[i-1];
   }
   
   g_lastTrades[0].open_time = TimeCurrent();
   g_lastTrades[0].ticket = ticket;
   g_lastTrades[0].symbol = symbol;
   g_lastTrades[0].action = action;
   g_lastTrades[0].entry_price = entry;
   g_lastTrades[0].sl = sl;
   g_lastTrades[0].tp = tp;
   g_lastTrades[0].risk_percent = risk;
   g_lastTrades[0].comment = comment;
}

//+------------------------------------------------------------------+
//| CHECK IF CURRENT SESSION IS VALID                                 |
//+------------------------------------------------------------------+
bool IsValidSession() {
   datetime serverTime = TimeCurrent();
   MqlDateTime dt;
   TimeToStruct(serverTime, dt);
   
   int hour = dt.hour;
   
   // WIB = UTC+7, server time may vary
   // Asian: 22-07 UTC → London: 07-16 UTC → NY: 12-21 UTC
   // Simplified by allowing all but Asian if configured
   
   // London session: 08:00-17:00 UTC
   if(hour >= 8 && hour < 17 && TradeLondon) return true;
   
   // NY session: 13:00-22:00 UTC  
   if(hour >= 13 && hour < 22 && TradeNY) return true;
   
   // Asian session: 23:00-08:00 UTC
   if((hour >= 23 || hour < 8) && TradeAsian) return true;
   
   return false;
}

//+------------------------------------------------------------------+
//| SIMPLE JSON VALUE EXTRACTOR                                       |
//+------------------------------------------------------------------+
string GetJSONValue(string json, string key) {
   string search = "\"" + key + "\"";
   int pos = StringFind(json, search);
   if(pos < 0) return "";
   
   // Find the colon after the key
   int colonPos = StringFind(json, ":", pos);
   if(colonPos < 0) return "";
   
   // Skip whitespace
   int valStart = colonPos + 1;
   while(valStart < StringLen(json)) {
      ushort ch = StringGetCharacter(json, valStart);
      if(ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') break;
      valStart++;
   }
   
   if(valStart >= StringLen(json)) return "";
   
   ushort firstChar = StringGetCharacter(json, valStart);
   
   if(firstChar == '"') {
      // String value
      valStart++; // skip opening quote
      int valEnd = StringFind(json, "\"", valStart);
      if(valEnd < 0) return "";
      return StringSubstr(json, valStart, valEnd - valStart);
   } else {
      // Numeric or boolean value
      int valEnd = valStart;
      while(valEnd < StringLen(json)) {
         ushort ch = StringGetCharacter(json, valEnd);
         if(ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\n' || ch == '\r') break;
         valEnd++;
      }
      return StringSubstr(json, valStart, valEnd - valStart);
   }
}

//+------------------------------------------------------------------+
//| LOAD/SAVE DAILY LOSS COUNT                                        |
//+------------------------------------------------------------------+
int LoadDailyLossCount() {
   // Load from global variable
   if(GlobalVariableCheck("PhantomFX_DailyLoss_" + IntegerToString(DayOfYear()))) {
      return (int)GlobalVariableGet("PhantomFX_DailyLoss_" + IntegerToString(DayOfYear()));
   }
   return 0;
}

void SaveDailyLossCount() {
   GlobalVariableSet("PhantomFX_DailyLoss_" + IntegerToString(DayOfYear()), g_lossCountToday);
}

//+------------------------------------------------------------------+
//| ON TRADE EVENT — Track wins/losses                                |
//+------------------------------------------------------------------+
void OnTrade() {
   // Check recently closed positions
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
                  PrintFormat("[LOSS #%d] Ticket: %d | PnL: %.2f", 
                             g_lossCountToday, ticket, profit);
               } else {
                  g_lossCountToday = 0; // Reset on win
                  PrintFormat("[WIN] Ticket: %d | PnL: %.2f | Loss streak reset", 
                             ticket, profit);
               }
            }
         }
      }
   }
}

//+------------------------------------------------------------------+
//| UTILITY: Day of Year                                              |
//+------------------------------------------------------------------+
int DayOfYear() {
   MqlDateTime dt;
   TimeCurrent(dt);
   return dt.day_of_year;
}

//+------------------------------------------------------------------+
//| ON CHART EVENT — Comment display                                  |
//+------------------------------------------------------------------+
void OnChartEvent(const int id, const long &lparam, const double &dparam, const string &sparam) {
   if(id == CHARTEVENT_CLICK) {
      // Show status on click
      string status = StringFormat(
         "⚡ PhantomFX EA v4.0\n"
         "━━━━━━━━━━━━━━━━━━━━\n"
         "Port: %d | Token: %s\n"
         "Balance: %.2f | Losses: %d/%d\n"
         "Daily P&L: %.2f | DD: %.2f%%\n"
         "Last Trade: %s\n"
         "━━━━━━━━━━━━━━━━━━━━\n"
         "Status: %s",
         WebhookPort, WebhookToken,
         AccountInfoDouble(ACCOUNT_BALANCE), g_lossCountToday, MaxDailyLosses,
         g_dailyPnL, (g_startingBalance - AccountInfoDouble(ACCOUNT_EQUITY)) / g_startingBalance * 100,
         TimeToString(g_lastTradeTime),
         g_webhookRunning ? "🟢 LISTENING" : "🔴 STOPPED"
      );
      Comment(status);
   }
}

//+------------------------------------------------------------------+
