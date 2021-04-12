namespace Bitvavo.API
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public class Bitvavo
    {
        private readonly Uri ApiUri = new Uri("https://api.bitvavo.com/v2");
        private readonly Uri SocketUri = new Uri("wss://ws.bitvavo.com/v2/");

        private readonly string ApiKey = "";
        private readonly string ApiSecret = "";
        private readonly int AccessWindow = 10000;

        private int RateLimitRemaining;
        private int RateLimitReset;

        private bool RateLimitThreadStarted;
        private readonly bool Debugging;

        private HttpClient Client { get; }

        private WebSocket WebSocket { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Bitvavo" /> class.
        /// </summary>
        /// <param name="apiKey">The API key.</param>
        /// <param name="apiSecret">The API secret.</param>
        /// <param name="accessWindow">The access window.</param>
        /// <param name="apiUri">The API URI.</param>
        /// <param name="socketUri">The socket URI.</param>
        /// <param name="debugging">if set to <c>true</c> [debugging].</param>
        public Bitvavo(string apiKey, string apiSecret, int accessWindow, string apiUri, string socketUri, bool debugging)
        {
            RateLimitRemaining = 1000;
            RateLimitReset = 0;
            ApiKey = !string.IsNullOrEmpty(apiKey) ? apiKey : ApiKey;
            ApiSecret = !string.IsNullOrEmpty(apiSecret) ? apiSecret : ApiSecret;
            AccessWindow = accessWindow != 0 ? accessWindow : AccessWindow;
            ApiUri = !string.IsNullOrEmpty(apiUri) ? new Uri(apiUri) : ApiUri;
            SocketUri = !string.IsNullOrEmpty(socketUri) ? new Uri(socketUri) : SocketUri;
            Debugging = debugging;
            Client = new HttpClient { BaseAddress = ApiUri };
            WebSocket = new WebSocket(ApiKey, ApiSecret, AccessWindow, SocketUri.ToString(), this);
        }

        /// <summary>
        /// Gets the API key.
        /// </summary>
        /// <returns></returns>
        public string GetApiKey()
        {
            return ApiKey;
        }

        /// <summary>
        /// Gets the API secret.
        /// </summary>
        /// <returns></returns>
        public string GetApiSecret()
        {
            return ApiSecret;
        }

        /// <summary>
        /// Creates the postfix.
        /// </summary>
        /// <param name="query">The query.</param>
        /// <param name="paramName">Name of the parameter.</param>
        /// <param name="paramValue">The parameter value.</param>
        /// <returns></returns>
        private static void AddQuery(ref string query, string paramName, string paramValue)
        {
            if (string.IsNullOrWhiteSpace(query) && !string.IsNullOrWhiteSpace(paramValue))
            {
                query = $"?{paramName}={WebUtility.UrlEncode(paramValue)}";
                return;
            }

            if (!string.IsNullOrWhiteSpace(query) && !string.IsNullOrWhiteSpace(paramValue))
            {
                query += $"&{paramName}={WebUtility.UrlEncode(paramValue)}";
            }
        }

        /// <summary>
        /// Creates the signature.
        /// </summary>
        /// <param name="timestamp">The timestamp.</param>
        /// <param name="method">The method.</param>
        /// <param name="urlEndpoint">The URL endpoint.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        public string CreateSignature(long timestamp, string method, string urlEndpoint, string body)
        {
            if (string.IsNullOrEmpty(ApiSecret) || string.IsNullOrEmpty(ApiKey))
            {
                ErrorToConsole("The API key or secret has not been set. Please pass the key and secret when instantiating the bitvavo object.");
                return "";
            }

            try
            {
                var result = $"{timestamp}{method}/v2{urlEndpoint}{body}";
                var encoding = new UTF8Encoding();
                var textBytes = encoding.GetBytes(result);
                var keyBytes = encoding.GetBytes(ApiSecret);
                using var hash = new HMACSHA256(keyBytes);
                var hashBytes = hash.ComputeHash(textBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch (Exception ex)
            {
                ErrorToConsole($"Caught exception in createSignature {ex}");
                return "";
            }
        }

        /// <summary>
        /// Debugs to console.
        /// </summary>
        /// <param name="message">The message.</param>
        public void DebugToConsole(string message)
        {
            if (!Debugging) return;
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} DEBUG: {message}");
        }

        /// <summary>
        /// Errors to console.
        /// </summary>
        /// <param name="message">The message.</param>
        public void ErrorToConsole(string message)
        {
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} ERROR: {message}");
        }

        /// <summary>
        /// Errors the rate limit.
        /// </summary>
        /// <param name="response">The response.</param>
        public void ErrorRateLimit(JObject response)
        {
            if (response.Value<int>("errorCode") != 105) return;
            RateLimitRemaining = 0;
            var message = response.Value<string>("error");
            var placeHolder = message.Split(" at ")[1].Replace(".", "");
            RateLimitReset = int.Parse(placeHolder);
            if (!RateLimitThreadStarted)
            {
                new Thread(() =>
                    {
                        try
                        {
                            var timeToWait = Convert.ToInt32(RateLimitReset - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                            RateLimitThreadStarted = true;
                            DebugToConsole($"We are waiting for {timeToWait / 1000} seconds, untill the rate limit ban will be lifted.");
                            Thread.Sleep(timeToWait);
                        }
                        catch (ThreadInterruptedException)
                        {
                            ErrorToConsole("Got interrupted while waiting for the rate limit ban to be lifted.");
                        }
                        RateLimitThreadStarted = false;
                        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < RateLimitReset) return;
                        DebugToConsole("Rate limit ban has been lifted, resetting rate limit to 1000.");
                        RateLimitRemaining = 1000;
                    }).Start();
            }
        }

        /// <summary>
        /// Updates the rate limit.
        /// </summary>
        /// <param name="headers">The headers.</param>
        public void UpdateRateLimit(HttpResponseHeaders headers)
        {
            if (headers.TryGetValues("Bitvavo-Ratelimit-Remaining", out var remainingHeaders))
            {
                RateLimitRemaining = int.Parse(remainingHeaders.First());
            }

            if (!headers.TryGetValues("Bitvavo-Ratelimit-ResetAt", out var resetHeader)) return;
            RateLimitReset = int.Parse(resetHeader.First());
            if (!RateLimitThreadStarted)
            {
                new Thread(() =>
                    {
                        try
                        {
                            var timeToWait = Convert.ToInt32(RateLimitReset - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                            RateLimitThreadStarted = true;
                            DebugToConsole($"We started a thread which waits for {timeToWait / 1000} seconds, untill the rate limit will be reset.");
                            Thread.Sleep(timeToWait);
                        }
                        catch (ThreadInterruptedException)
                        {
                            ErrorToConsole("Got interrupted while waiting for the rate limit to be reset.");
                        }
                        RateLimitThreadStarted = false;
                        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() < RateLimitReset) return;
                        DebugToConsole("Resetting rate limit to 1000.");
                        RateLimitRemaining = 1000;
                    }).Start();
            }
        }

        /// <summary>
        /// Gets the remaining limit.
        /// </summary>
        /// <returns></returns>
        public int GetRemainingLimit()
        {
            return RateLimitRemaining;
        }

        /// <summary>
        /// Processes the web request.
        /// </summary>
        /// <param name="urlString">The URL string.</param>
        /// <param name="method">The method.</param>
        /// <param name="jsonBody">The json body.</param>
        /// <returns>The JToken created from the response.</returns>
        private JToken WebRequest(string urlString, HttpMethod method, JToken jsonBody)
        {
            try
            {
                var bodyString = jsonBody.ToString(Formatting.None);
                if (!string.IsNullOrEmpty(ApiKey) && !string.IsNullOrEmpty(ApiSecret))
                {
                    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var signature = CreateSignature(timestamp, method.ToString(), (urlString), bodyString);
                    Client.DefaultRequestHeaders.Add("Bitvavo-Access-Key", ApiKey);
                    Client.DefaultRequestHeaders.Add("Bitvavo-Access-Signature", signature);
                    Client.DefaultRequestHeaders.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                    Client.DefaultRequestHeaders.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                }

                var request = new HttpRequestMessage(method, urlString)
                {
                    Content = string.IsNullOrEmpty(bodyString)
                                                    ? new StringContent("")
                                                    : new StringContent(bodyString, Encoding.UTF8, "application/json"),
                };

                var response = Client.SendAsync(request).Result;
                if (response.IsSuccessStatusCode)
                {
                    UpdateRateLimit(response.Headers);
                }

                var result = response.Content.ReadAsStringAsync().Result;

                if (result.Contains("errorCode"))
                {
                    ErrorRateLimit(JObject.Parse(result));
                }

                return JToken.Parse(result);
            }
            catch (Exception ex)
            {
                ErrorToConsole($"Caught exception in privateRequest {ex}");
                return new JObject();
            }
        }

        /// <summary>
        /// Processes the web request.
        /// </summary>
        /// <param name="urlString">The URL string.</param>
        /// <param name="method">The method.</param>
        /// <returns>The JToken created from the response.</returns>
        private JToken WebRequest(string urlString, HttpMethod method) => WebRequest(urlString, method, new JObject());

        /// <summary>
        /// Returns the current timestamp in milliseconds since 1 Jan 1970.
        /// This can be useful if you need to synchronise your time with the Bitvavo servers.
        /// </summary>
        /// <returns>The JObject response.</returns>
        public JObject Time()
        {
            return (JObject)WebRequest($"{ApiUri}/time", HttpMethod.Get);
        }

        public JArray Markets(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            return (JArray)WebRequest($"{ApiUri}/markets{query}", HttpMethod.Get);
        }

        public JArray Assets(string symbol)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(symbol), symbol);
            return (JArray)WebRequest($"{ApiUri}/assets{query}", HttpMethod.Get);
        }

        public JObject Book(string market, int depth)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(depth), depth.ToString());
            return (JObject)WebRequest($"{ApiUri}/{market}/book", HttpMethod.Get);
        }

        public JArray PublicTrades(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            return (JArray)WebRequest($"{ApiUri}/{market}/trades{query}", HttpMethod.Get);
        }

        public JArray Candles(string market, string interval, int limit, long start, long end)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(interval), interval);
            AddQuery(ref query, nameof(limit), limit.ToString());
            AddQuery(ref query, nameof(start), start.ToString());
            AddQuery(ref query, nameof(end), end.ToString());
            return (JArray)WebRequest($"{ApiUri}/{market}/candles{query}", HttpMethod.Get);
        }

        public JArray TickerPrice(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            var response = WebRequest($"{ApiUri}/ticker/price{query}", HttpMethod.Get);
            return response.Type == JTokenType.Array ? (JArray)response : new JArray(response);
        }

        public JArray TickerBook(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            var response = WebRequest($"{ApiUri}/ticker/book{query}", HttpMethod.Get);
            return response.Type == JTokenType.Array ? (JArray)response : new JArray(response);
        }

        public JArray Ticker24H(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            var response = WebRequest($"{ApiUri}/ticker/24h{query}", HttpMethod.Get);
            return response.Type == JTokenType.Array ? (JArray)response : new JArray(response);
        }

        public JObject PlaceOrder(string market, string side, string orderType, JObject body)
        {
            body.Add("market", market);
            body.Add("side", side);
            body.Add("orderType", orderType);
            return (JObject)WebRequest($"{ApiUri}/order", HttpMethod.Post, body);
        }

        public JObject GetOrder(string market, string orderId)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(orderId), orderId);
            return (JObject)WebRequest($"{ApiUri}/order", HttpMethod.Get);
        }

        public JObject UpdateOrder(string market, string orderId, JObject body)
        {
            body.Add("market", market);
            body.Add("orderId", orderId);
            return (JObject)WebRequest($"{ApiUri}/order", HttpMethod.Put, body);
        }

        public JObject CancelOrder(string market, string orderId)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(orderId), orderId);
            return (JObject)WebRequest($"{ApiUri}/order{query}", HttpMethod.Delete);
        }

        public JArray GetOrders(string market, int limit, long start, long end, string orderIdFrom, string orderIdTo)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(limit), limit.ToString());
            AddQuery(ref query, nameof(start), start.ToString());
            AddQuery(ref query, nameof(end), end.ToString());
            AddQuery(ref query, nameof(orderIdFrom), orderIdFrom);
            AddQuery(ref query, nameof(orderIdTo), orderIdTo);
            return (JArray)WebRequest($"{ApiUri}/orders{query}", HttpMethod.Get);
        }

        public JArray CancelOrders(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            return (JArray)WebRequest($"{ApiUri}/orders{query}", HttpMethod.Delete);
        }

        public JArray OrdersOpen(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            return (JArray)WebRequest($"{ApiUri}/ordersOpen{query}", HttpMethod.Get);
        }

        public JArray Trades(string market, int limit, long start, long end, string tradeIdFrom, string tradeIdTo)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            AddQuery(ref query, nameof(limit), limit.ToString());
            AddQuery(ref query, nameof(start), start.ToString());
            AddQuery(ref query, nameof(end), end.ToString());
            AddQuery(ref query, nameof(tradeIdFrom), tradeIdFrom);
            AddQuery(ref query, nameof(tradeIdTo), tradeIdTo);
            return (JArray)WebRequest($"{ApiUri}/trades{query}", HttpMethod.Get);
        }

        public JObject Account()
        {
            return (JObject)WebRequest($"{ApiUri}/options", HttpMethod.Get);
        }

        public JArray Balance(string symbol)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(symbol), symbol);
            return (JArray)WebRequest($"{ApiUri}/options{query}", HttpMethod.Get);
        }

        public JObject DepositAssets(string symbol)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(symbol), symbol);
            return (JObject)WebRequest($"{ApiUri}/deposit{query}", HttpMethod.Get);
        }

        public JObject WithdrawAssets(string symbol, string amount, string address, JObject body)
        {
            body.Add("symbol", symbol);
            body.Add("amount", amount);
            body.Add("address", address);
            return (JObject)WebRequest($"{ApiUri}/withdrawal", HttpMethod.Post, body);
        }

        public JArray DepositHistory(string symbol, int limit, long start, long end)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(symbol), symbol);
            AddQuery(ref query, nameof(limit), limit.ToString());
            AddQuery(ref query, nameof(start), start.ToString());
            AddQuery(ref query, nameof(end), end.ToString());
            return (JArray)WebRequest($"{ApiUri}/depositHistory{query}", HttpMethod.Get);
        }

        public JArray WithdrawalHistory(string symbol, int limit, long start, long end)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(symbol), symbol);
            AddQuery(ref query, nameof(limit), limit.ToString());
            AddQuery(ref query, nameof(start), start.ToString());
            AddQuery(ref query, nameof(end), end.ToString());
            return (JArray)WebRequest($"{ApiUri}/withdrawalHistory{query}", HttpMethod.Get);
        }

        public WebSocket NewWebsocket()
        {
            var webSocketClient = new WebSocket();
            return webSocketClient;
        }

        void HandleBook(Runnable function)
        {
            function.run();
        }

        public void Close()
        {
            ws.closeSocket();
        }

        public void DoSendPublic(JObject options)
        {
            ws.sendMessage(options.toString());
        }

        public void DoSendPrivate(JObject options)
        {
            if (string.IsNullOrEmpty(ApiKey) || string.IsNullOrEmpty(ApiSecret))
            {
                ErrorToConsole("You forgot to set the key and secret, both are required for this functionality.");
            }
            else if (authenticated)
            {
                ws.sendMessage(options.toString());
            }
            else
            {
                try
                {
                    Thread.Sleep(50);
                    DoSendPrivate(options);
                }
                catch (ThreadInterruptedException)
                {
                    ErrorToConsole("Interrupted, aborting send.");
                }
            }
        }

        public void SetErrorCallback(WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addErrorHandler(msgHandler);
        }

        public void Time(WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTimeHandler(msgHandler);
            DoSendPublic(new JObject("{ action: getTime }"));
        }

        public void Markets(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addMarketsHandler(msgHandler);
            options.Add("action", "getMarkets");
            DoSendPublic(options);
        }

        public void Assets(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addAssetsHandler(msgHandler);
            options.Add("action", "getAssets");
            DoSendPublic(options);
        }


        public void Book(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addBookHandler(msgHandler);
            options.Add("action", "getBook");
            options.Add("market", market);
            DoSendPublic(options);
        }


        public void PublicTrades(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTradesHandler(msgHandler);
            options.Add("action", "getTrades");
            options.Add("market", market);
            DoSendPublic(options);
        }


        public void Candles(string market, string interval, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCandlesHandler(msgHandler);
            options.Add("action", "getCandles");
            options.Add("market", market);
            options.Add("interval", interval);
            DoSendPublic(options);
        }


        public void Ticker24H(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTicker24hHandler(msgHandler);
            options.Add("action", "getTicker24h");
            DoSendPublic(options);
        }


        public void TickerPrice(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTickerPriceHandler(msgHandler);
            options.Add("action", "getTickerPrice");
            DoSendPublic(options);
        }


        public void TickerBook(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTickerBookHandler(msgHandler);
            options.Add("action", "getTickerBook");
            DoSendPublic(options);
        }


        public void PlaceOrder(string market, string side, string orderType, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addPlaceOrderHandler(msgHandler);
            body.Add("market", market);
            body.Add("side", side);
            body.Add("orderType", orderType);
            body.Add("action", "privateCreateOrder");
            DoSendPrivate(body);
        }


        public void GetOrder(string market, string orderId, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrderHandler(msgHandler);
            var options = new JObject();
            options.Add("action", "privateGetOrder");
            options.Add("market", market);
            options.Add("orderId", orderId);
            DoSendPrivate(options);
        }


        public void UpdateOrder(string market, string orderId, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addUpdateOrderHandler(msgHandler);
            body.Add("market", market);
            body.Add("orderId", orderId);
            body.Add("action", "privateUpdateOrder");
            DoSendPrivate(body);
        }


        public void CancelOrder(string market, string orderId, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCancelOrderHandler(msgHandler);
            var options = new JObject();
            options.Add("action", "privateCancelOrder");
            options.Add("market", market);
            options.Add("orderId", orderId);
            DoSendPrivate(options);
        }


        public void GetOrders(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrdersHandler(msgHandler);
            options.Add("action", "privateGetOrders");
            options.Add("market", market);
            DoSendPrivate(options);
        }


        public void CancelOrders(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCancelOrdersHandler(msgHandler);
            options.Add("action", "privateCancelOrders");
            DoSendPrivate(options);
        }


        public void OrdersOpen(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrdersOpenHandler(msgHandler);
            options.Add("action", "privateGetOrdersOpen");
            DoSendPrivate(options);
        }


        public void Trades(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetTradesHandler(msgHandler);
            options.Add("action", "privateGetTrades");
            options.Add("market", market);
            DoSendPrivate(options);
        }


        public void Account(WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addAccountHandler(msgHandler);
            var options = new JObject("{ action: privateGetAccount }");
            DoSendPrivate(options);
        }


        public void Balance(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addBalanceHandler(msgHandler);
            options.Add("action", "privateGetBalance");
            DoSendPrivate(options);
        }


        public void DepositAssets(string symbol, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addDepositAssetsHandler(msgHandler);
            var options = new JObject("{ action: privateDepositAssets }");
            options.Add("symbol", symbol);
            DoSendPrivate(options);
        }


        public void WithdrawAssets(string symbol, string amount, string address, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addWithdrawAssetsHandler(msgHandler);
            body.Add("action", "privateWithdrawAssets");
            body.Add("symbol", symbol);
            body.Add("amount", amount);
            body.Add("address", address);
            DoSendPrivate(body);
        }


        public void DepositHistory(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addDepositHistoryHandler(msgHandler);
            options.Add("action", "privateGetDepositHistory");
            DoSendPrivate(options);
        }


        public void WithdrawalHistory(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addWithdrawalHistoryHandler(msgHandler);
            options.Add("action", "privateGetWithdrawalHistory");
            DoSendPrivate(options);
        }


        public void SubscriptionTicker(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTickerHandler(market, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "ticker");
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionTicker = true;
            if (optionsSubscriptionTicker == null)
            {
                optionsSubscriptionTicker = new JObject();
            }
            optionsSubscriptionTicker.Add(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionTicker24H(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTicker24hHandler(market, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "ticker24h");
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionTicker24h = true;
            if (optionsSubscriptionTicker24h == null)
            {
                optionsSubscriptionTicker24h = new JObject();
            }
            optionsSubscriptionTicker24h.Add(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionAccount(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionAccountHandler(market, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "account");
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionAccount = true;
            if (optionsSubscriptionAccount == null)
            {
                optionsSubscriptionAccount = new JObject();
            }
            optionsSubscriptionAccount.Add(market, options);
            DoSendPrivate(options);
        }

        public void SubscriptionCandles(string market, string interval, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionCandlesHandler(market, interval, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "candles");
            subOptions.Add("interval", new string[] { interval });
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionCandles = true;
            var intervalIndex = new JObject();
            intervalIndex.Add(interval, options);
            if (optionsSubscriptionCandles == null)
            {
                optionsSubscriptionCandles = new JObject();
            }
            optionsSubscriptionCandles.Add(market, intervalIndex);
            DoSendPublic(options);
        }


        public void SubscriptionTrades(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTradesHandler(market, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "trades");
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionTrades = true;
            if (optionsSubscriptionTrades == null)
            {
                optionsSubscriptionTrades = new JObject();
            }
            optionsSubscriptionTrades.Add(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionBookUpdate(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionBookUpdateHandler(market, msgHandler);
            var options = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "book");
            subOptions.Add("markets", new string[] { market });
            options.Add("action", "subscribe");
            options.Add("channels", new JObject[] { subOptions });
            activatedSubscriptionBookUpdate = true;
            if (optionsSubscriptionBookUpdate == null)
            {
                optionsSubscriptionBookUpdate = new JObject();
            }
            optionsSubscriptionBookUpdate.Add(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionBook(string market, WebsocketClientEndpoint.BookHandler msgHandler)
        {
            ws.keepBookCopy = true;
            Map<string, object> bidsAsks = new HashMap<string, object>();
            bidsAsks.Add("bids", new ArrayList<ArrayList<Float>>());
            bidsAsks.Add("asks", new ArrayList<ArrayList<Float>>());

            Book.Add(market, bidsAsks);
            ws.addSubscriptionBookHandler(market, msgHandler);
            var options = new JObject();
            options.Add("action", "getBook");
            options.Add("market", market);
            activatedSubscriptionBook = true;
            if (optionsSubscriptionBookFirst == null)
            {
                optionsSubscriptionBookFirst = new JObject();
            }
            optionsSubscriptionBookFirst.Add(market, options);
            DoSendPublic(options);

            var secondOptions = new JObject();
            var subOptions = new JObject();
            subOptions.Add("name", "book");
            subOptions.Add("markets", new string[] { market });
            secondOptions.Add("action", "subscribe");
            secondOptions.Add("channels", new JObject[] { subOptions });
            if (optionsSubscriptionBookSecond == null)
            {
                optionsSubscriptionBookSecond = new JObject();
            }
            optionsSubscriptionBookSecond.Add(market, secondOptions);
            DoSendPublic(secondOptions);
        }
    }
}
