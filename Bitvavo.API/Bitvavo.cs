namespace Bitvavo.API
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public class Bitvavo
    {
        private Uri ApiUri = new Uri("https://api.bitvavo.com/v2");
        private Uri SocketUri = new Uri("wss://ws.bitvavo.com/v2/");

        private readonly string ApiKey;
        private readonly string ApiSecret;
        private readonly int AccessWindow = 10000;

        private int RateLimitRemaining;
        private int RateLimitReset;

        private bool RateLimitThreadStarted;
        private readonly bool Debugging;

        /// <summary>
        /// Initializes a new instance of the <see cref="Bitvavo" /> class.
        /// </summary>
        /// <param name="apiKey">The API key.</param>
        /// <param name="apiSecret">The API secret.</param>
        /// <param name="accessWindow">The access window.</param>
        /// <param name="ApiUri">The rest URL.</param>
        /// <param name="webSocketUrl">The web socket URL.</param>
        /// <param name="debugging">if set to <c>true</c> [debugging].</param>
        public Bitvavo(string apiKey, string apiSecret, int accessWindow, string ApiUri, string webSocketUrl, bool debugging)
        {
            RateLimitRemaining = 1000;
            RateLimitReset = 0;

            ApiKey = !string.IsNullOrEmpty(apiKey) ? apiKey : "";
            ApiSecret = !string.IsNullOrEmpty(apiSecret) ? apiSecret : "";
            AccessWindow = accessWindow != 0 ? accessWindow : AccessWindow;
            Debugging = debugging;
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
        /// <param name="options">The options.</param>
        /// <returns></returns>
        private string CreatePostfix(JObject options)
        {
            var keys = options
                .Properties()
                .Select(p => p.Name)
                .ToList();

            var array = keys
                .Select(key => $"{key}={options.GetValue(key)}")
                .ToList();

            var parameters = string.Join("&", array);
            if (keys.First())
            {
                parameters = "?" + parameters;
            }
            return parameters;
        }

        /// <summary>
        /// Creates the signature.
        /// </summary>
        /// <param name="timestamp">The timestamp.</param>
        /// <param name="method">The method.</param>
        /// <param name="urlEndpoint">The URL endpoint.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        public string CreateSignature(long timestamp, string method, string urlEndpoint, JObject body)
        {
            if (ApiSecret == null || ApiKey == null)
            {
                ErrorToConsole("The API key or secret has not been set. Please pass the key and secret when instantiating the bitvavo object.");
                return "";
            }
            try
            {
                var result = $"{timestamp}{method}/v2{urlEndpoint}";
                if (body.Count != 0)
                {
                    result += body.ToString(Formatting.None);
                }

                var encoding = new UTF8Encoding();
                var textBytes = encoding.GetBytes(result);
                var keyBytes = encoding.GetBytes(ApiSecret);
                using var hash = new HMACSHA256(keyBytes);
                var hashBytes = hash.ComputeHash(textBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch (Exception ex)
            {
                ErrorToConsole("Caught exception in createSignature " + ex);
                return "";
            }
        }

        /// <summary>
        /// Debugs to console.
        /// </summary>
        /// <param name="message">The message.</param>
        public void DebugToConsole(string message)
        {
            if (Debugging)
            {
                Console.WriteLine($"{DateTime.Now:HH:mm:ss} DEBUG: " + message);
            }
        }

        /// <summary>
        /// Errors to console.
        /// </summary>
        /// <param name="message">The message.</param>
        public void ErrorToConsole(string message)
        {
            Console.WriteLine($"{DateTime.Now:HH:mm:ss} ERROR: " + message);
        }

        /// <summary>
        /// Errors the rate limit.
        /// </summary>
        /// <param name="response">The response.</param>
        public void ErrorRateLimit(JObject response)
        {
            if (response.Value<int>("errorCode") == 105)
            {
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
                                DebugToConsole("We are waiting for " + (timeToWait / 1000) + " seconds, untill the rate limit ban will be lifted.");
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
        }


        /// <summary>
        /// Updates the rate limit.
        /// </summary>
        /// <param name="headers">The headers.</param>
        public void UpdateRateLimit(WebHeaderCollection headers)
        {
            var remainingHeader = headers.Get("Bitvavo-Ratelimit-Remaining");
            var resetHeader = headers.Get("Bitvavo-Ratelimit-ResetAt");
            if (remainingHeader != null)
            {
                RateLimitRemaining = int.Parse(remainingHeader);
            }
            if (resetHeader != null)
            {
                RateLimitReset = int.Parse(resetHeader);
                if (!RateLimitThreadStarted)
                {
                    new Thread(new ThreadStart(() =>
                    {
                        try
                        {
                            var timeToWait = Convert.ToInt32(RateLimitReset - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                            RateLimitThreadStarted = true;
                            DebugToConsole("We started a thread which waits for " + (timeToWait / 1000) + " seconds, untill the rate limit will be reset.");
                            Thread.Sleep(timeToWait);
                        }
                        catch (ThreadInterruptedException)
                        {
                            ErrorToConsole("Got interrupted while waiting for the rate limit to be reset.");
                        }
                        RateLimitThreadStarted = false;
                        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= RateLimitReset)
                        {
                            DebugToConsole("Resetting rate limit to 1000.");
                            RateLimitRemaining = 1000;
                        }
                    })).Start();
                }
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
        /// Privates the request.
        /// </summary>
        /// <param name="urlEndpoint">The URL endpoint.</param>
        /// <param name="urlParams">The URL parameters.</param>
        /// <param name="method">The method.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        public JObject PrivateRequest(string urlEndpoint, string urlParams, string method, JObject body)
        {
            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var signature = CreateSignature(timestamp, method, (urlEndpoint + urlParams), body);
                var url = new Uri(ApiUri + urlEndpoint + urlParams);
                var httpsCon = (HttpWebRequest)WebRequest.Create(url);

                httpsCon.Method = method;
                httpsCon.Headers.Add("Bitvavo-Access-Key", ApiKey);
                httpsCon.Headers.Add("Bitvavo-Access-Signature", signature);
                httpsCon.Headers.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                httpsCon.Headers.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                httpsCon.ContentType = "application/json";

                if (body.Count != 0)
                {
                    using var streamWriter = new StreamWriter(httpsCon.GetRequestStream());
                    var json = JsonConvert.SerializeObject(body);
                    streamWriter.Write(json);
                    streamWriter.Flush();
                    streamWriter.Close();
                }

                using var myHttpWebResponse = (HttpWebResponse)httpsCon.GetResponse();
                var responseCode = (int)myHttpWebResponse.StatusCode;
                using var reader = new StreamReader(myHttpWebResponse.GetResponseStream());
                if (responseCode == 200)
                {
                    this.UpdateRateLimit(myHttpWebResponse.Headers);
                }

                var responseFromServer = reader.ReadToEnd();
                var response = JObject.Parse(responseFromServer);
                if (responseFromServer.Contains("errorCode"))
                {
                    this.ErrorRateLimit(response);
                }
                return response;
            }
            catch (Exception ex)
            {
                ErrorToConsole("Caught exception in privateRequest " + ex);
                return new JObject();
            }
        }

        /// <summary>
        /// Privates the request array.
        /// </summary>
        /// <param name="urlEndpoint">The URL endpoint.</param>
        /// <param name="urlParams">The URL parameters.</param>
        /// <param name="method">The method.</param>
        /// <param name="body">The body.</param>
        /// <returns></returns>
        public JArray PrivateRequestArray(string urlEndpoint, string urlParams, string method, JObject body)
        {
            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var signature = CreateSignature(timestamp, method, (urlEndpoint + urlParams), body);
                var url = new Uri(ApiUri + urlEndpoint + urlParams);
                var httpsCon = (HttpWebRequest)WebRequest.Create(url);

                httpsCon.Method = method;
                httpsCon.Headers.Add("Bitvavo-Access-Key", ApiKey);
                httpsCon.Headers.Add("Bitvavo-Access-Signature", signature);
                httpsCon.Headers.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                httpsCon.Headers.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                httpsCon.ContentType = "application/json";
                if (body.Count != 0)
                {
                    using var streamWriter = new StreamWriter(httpsCon.GetRequestStream());
                    var json = JsonConvert.SerializeObject(body);
                    streamWriter.Write(json);
                    streamWriter.Flush();
                    streamWriter.Close();
                }

                using var myHttpWebResponse = (HttpWebResponse)httpsCon.GetResponse();
                var responseCode = (int)myHttpWebResponse.StatusCode;
                using var reader = new StreamReader(myHttpWebResponse.GetResponseStream());
                if (responseCode == 200)
                {
                    UpdateRateLimit(myHttpWebResponse.Headers);
                }

                var responseFromServer = reader.ReadToEnd();
                if (responseFromServer.Contains("errorCode"))
                {
                    ErrorRateLimit(new JObject(responseFromServer));
                }
                var response = JArray.Parse(responseFromServer);
                return response;
            }
            catch (Exception ex)
            {
                ErrorToConsole("Caught exception in privateRequest " + ex);
                return new JArray();
            }
        }

        /// <summary>
        /// Publics the request.
        /// </summary>
        /// <param name="urlString">The URL string.</param>
        /// <param name="method">The method.</param>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public JObject PublicRequest(string urlString, string method, JObject data)
        {
            try
            {
                var url = new Uri(urlString);
                var httpsCon = (HttpWebRequest)WebRequest.Create(url);
                httpsCon.Method = method;
                if (!string.IsNullOrEmpty(ApiKey))
                {
                    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var signature = CreateSignature(timestamp, method, urlString.Replace(ApiUri.ToString(), ""), new JObject());
                    httpsCon.Headers.Add("Bitvavo-Access-Key", ApiKey);
                    httpsCon.Headers.Add("Bitvavo-Access-Signature", signature);
                    httpsCon.Headers.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                    httpsCon.Headers.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                    httpsCon.ContentType = "application/json";
                }
                using var myHttpWebResponse = (HttpWebResponse)httpsCon.GetResponse();
                var responseCode = (int)myHttpWebResponse.StatusCode;
                using var reader = new StreamReader(myHttpWebResponse.GetResponseStream());
                if (responseCode == 200)
                {
                    UpdateRateLimit(myHttpWebResponse.Headers);
                }

                var responseFromServer = reader.ReadToEnd();
                if (responseFromServer.Contains("errorCode"))
                {
                    ErrorRateLimit(new JObject(responseFromServer));
                }
                var response = JObject.Parse(responseFromServer);
                return response;
            }
            catch (IOException ex)
            {
                ErrorToConsole("Caught IOerror, " + ex);
            }
            return new JObject();
        }

        /// <summary>
        /// Publics the request array.
        /// </summary>
        /// <param name="urlString">The URL string.</param>
        /// <param name="method">The method.</param>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public JArray PublicRequestArray(string urlString, string method, JObject data)
        {
            try
            {
                var url = new Uri(urlString);
                var httpsCon = (HttpWebRequest)WebRequest.Create(url);
                httpsCon.Method = method;
                if (!string.IsNullOrEmpty(ApiKey))
                {
                    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var signature = CreateSignature(timestamp, method, urlString.Replace(ApiUri.ToString(), ""), new JObject());
                    httpsCon.Headers.Add("Bitvavo-Access-Key", ApiKey);
                    httpsCon.Headers.Add("Bitvavo-Access-Signature", signature);
                    httpsCon.Headers.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                    httpsCon.Headers.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                    httpsCon.ContentType = "application/json";
                }
                using var myHttpWebResponse = (HttpWebResponse)httpsCon.GetResponse();
                var responseCode = (int)myHttpWebResponse.StatusCode;
                using var reader = new StreamReader(myHttpWebResponse.GetResponseStream());
                if (responseCode == 200)
                {
                    UpdateRateLimit(myHttpWebResponse.Headers);
                }

                var responseFromServer = reader.ReadToEnd();
                if (responseFromServer.IndexOf("error") != -1)
                {
                    ErrorRateLimit(new JObject(responseFromServer));
                    return new JArray("[" + responseFromServer + "]");
                }
                DebugToConsole("FULL RESPONSE: " + responseFromServer);
                var response = JArray.Parse(responseFromServer);
                return response;
            }
            catch (IOException ex)
            {
                ErrorToConsole("Caught IOerror, " + ex);
            }
            return new JArray();
        }

        /// <summary>
        /// Times this instance.
        /// </summary>
        /// <returns></returns>
        public JObject Time()
        {
            return PublicRequest((this.ApiUri + "/time"), "GET", new JObject());
        }

        /**
 * Returns the available markets
 * @param options optional parameters: market
 * @return JArray response, get markets by iterating over array: response.get(index)
 */
        public JArray Markets(JObject options)
        {
            string postfix = CreatePostfix(options);
            if (options.has("market"))
            {
                JArray returnArray = new JArray();
                returnArray.put(PublicRequest((this.ApiUri + "/markets" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((this.ApiUri + "/markets" + postfix), "GET", new JObject());
            }
        }

        /**
         * Returns the available assets
         * @param options optional parameters: symbol
         * @return JArray response, get assets by iterating over array response.get(index)
         */
        public JArray Assets(JObject options)
        {
            string postfix = CreatePostfix(options);
            if (options.has("symbol"))
            {
                JArray returnArray = new JArray();
                returnArray.put(PublicRequest((this.ApiUri + "/assets" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((this.ApiUri + "/assets" + postfix), "GET", new JObject());
            }
        }

        /**
         * Returns the book for a certain market
         * @param market Specifies the market for which the book should be returned.
         * @param options optional parameters: depth
         * @return JObject response, get bids through response.getJArray("bids"), asks through response.getJArray("asks")
         */
        public JObject Book(string market, JObject options)
        {
            string postfix = CreatePostfix(options);
            return PublicRequest((this.ApiUri + "/" + market + "/book" + postfix), "GET", new JObject());
        }

        /**
         * Returns the trades for a specific market
         * @param market Specifies the market for which trades should be returned
         * @param options optional parameters: limit, start, end, tradeIdFrom, tradeIdTo
         * @return JArray response, iterate over array to get individual trades response.getJObject(index)
         */
        public JArray PublicTrades(string market, JObject options)
        {
            string postfix = CreatePostfix(options);
            return PublicRequestArray((this.ApiUri + "/" + market + "/trades" + postfix), "GET", new JObject());
        }

        /**
         *  Returns the candles for a specific market
         * @param market market for which the candles should be returned
         * @param interval interval on which the candles should be returned
         * @param options optional parameters: limit, start, end
         * @return JArray response, get individual candles through response.getJArray(index)
         */
        public JArray Candles(string market, string interval, JObject options)
        {
            options.put("interval", interval);
            string postfix = CreatePostfix(options);
            return PublicRequestArray((this.ApiUri + "/" + market + "/candles" + postfix), "GET", new JObject());
        }

        /**
         * Returns the ticker price
         * @param options optional parameters: market
         * @return JArray response, get individual prices by iterating over array: response.getJObject(index)
         */
        public JArray TickerPrice(JObject options)
        {
            string postfix = CreatePostfix(options);
            if (options.has("market"))
            {
                JArray returnArray = new JArray();
                returnArray.put(PublicRequest((this.ApiUri + "/ticker/price" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((this.ApiUri + "/ticker/price" + postfix), "GET", new JObject());
            }
        }

        /**
         * Return the book ticker
         * @param options optional parameters: market
         * @return JArray response, get individual books by iterating over array: response.getJObject(index)
         */
        public JArray TickerBook(JObject options)
        {
            string postfix = CreatePostfix(options);
            if (options.has("market"))
            {
                JArray returnArray = new JArray();
                returnArray.put(PublicRequest((this.ApiUri + "/ticker/book" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((this.ApiUri + "/ticker/book" + postfix), "GET", new JObject());
            }
        }

        /**
         * Return the 24 hour ticker
         * @param options optional parameters: market
         * @return JArray response, get individual 24 hour prices by iterating over array: response.getJObject(index)
         */
        public JArray Ticker24H(JObject options)
        {
            string postfix = CreatePostfix(options);
            if (options.has("market"))
            {
                JArray returnArray = new JArray();
                returnArray.put(PublicRequest((this.ApiUri + "/ticker/24h" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((this.ApiUri + "/ticker/24h" + postfix), "GET", new JObject());
            }
        }

        /**
         * Places an order on the exchange
         * @param market The market for which the order should be created
         * @param side is this a buy or sell order
         * @param orderType is this a limit or market order
         * @param body optional body parameters: limit:(amount, price, postOnly), market:(amount, amountQuote, disableMarketProtection)
         *                                       stopLoss/takeProfit:(amount, amountQuote, disableMarketProtection, triggerType, triggerReference, triggerAmount)
         *                                       stopLossLimit/takeProfitLimit:(amount, price, postOnly, triggerType, triggerReference, triggerAmount)
         *                                       all orderTypes: timeInForce, selfTradePrevention, responseRequired
         * @return JObject response, get status of the order through response.getString("status")
         */
        public JObject PlaceOrder(string market, string side, string orderType, JObject body)
        {
            body.put("market", market);
            body.put("side", side);
            body.put("orderType", orderType);
            return privateRequest("/order", "", "POST", body);
        }

        /**
         * Returns a specific order
         * @param market the market the order resides on
         * @param orderId the id of the order
         * @return JObject response, get status of the order through response.getString("status")
         */
        public JObject GetOrder(string market, string orderId)
        {
            JObject options = new JObject();
            options.put("market", market);
            options.put("orderId", orderId);
            string postfix = CreatePostfix(options);
            return privateRequest("/order", postfix, "GET", new JObject());
        }

        /**
         * Updates an order
         * @param market the market the order resides on
         * @param orderId the id of the order which should be updated
         * @param body optional body parameters: limit:(amount, amountRemaining, price, timeInForce, selfTradePrevention, postOnly)
         *                           untriggered stopLoss/takeProfit:(amount, amountQuote, disableMarketProtection, triggerType, triggerReference, triggerAmount)
         *                                       stopLossLimit/takeProfitLimit: (amount, price, postOnly, triggerType, triggerReference, triggerAmount)
         * @return JObject response, get status of the order through response.getString("status")
         */
        public JObject UpdateOrder(string market, string orderId, JObject body)
        {
            body.put("market", market);
            body.put("orderId", orderId);
            return privateRequest("/order", "", "PUT", body);
        }

        /**
         * Cancel an order
         * @param market the market the order resides on
         * @param orderId the id of the order which should be cancelled
         * @return JObject response, get the id of the order which was cancelled through response.getString("orderId")
         */
        public JObject CancelOrder(string market, string orderId)
        {
            JObject options = new JObject();
            options.put("market", market);
            options.put("orderId", orderId);
            string postfix = CreatePostfix(options);
            return privateRequest("/order", postfix, "DELETE", new JObject());
        }

        /**
         * Returns multiple orders for a specific market
         * @param market the market for which orders should be returned
         * @param options optional parameters: limit, start, end, orderIdFrom, orderIdTo
         * @return JArray response, get individual orders by iterating over array: response.getJObject(index)
         */
        public JArray GetOrders(string market, JObject options)
        {
            options.put("market", market);
            string postfix = CreatePostfix(options);
            return privateRequestArray("/orders", postfix, "GET", new JObject());
        }

        /**
         * Cancel multiple orders at once, if no market is specified all orders will be canceled
         * @param options optional parameters: market
         * @return JArray response, get individual cancelled orderId's by iterating over array: response.getJObject(index).getString("orderId")
         */
        public JArray CancelOrders(JObject options)
        {
            string postfix = CreatePostfix(options);
            return privateRequestArray("/orders", postfix, "DELETE", new JObject());
        }

        /**
         * Returns all open orders for an account
         * @param options optional parameters: market
         * @return JArray response, get individual orders by iterating over array: response.getJObject(index)
         */
        public JArray OrdersOpen(JObject options)
        {
            string postfix = CreatePostfix(options);
            return privateRequestArray("/ordersOpen", postfix, "GET", new JObject());
        }

        /**
         * Returns all trades for a specific market
         * @param market the market for which trades should be returned
         * @param options optional parameters: limit, start, end, tradeIdFrom, tradeIdTo
         * @return JArray trades, get individual trades by iterating over array: response.getJObject(index)
         */
        public JArray Trades(string market, JObject options)
        {
            options.put("market", market);
            string postfix = CreatePostfix(options);
            return privateRequestArray("/trades", postfix, "GET", new JObject());
        }

        /**
         * Return the fee tier for an account
         * @return JObject response, get taker fee through: response.getJObject("fees").getString("taker")
         */
        public JObject Account()
        {
            return privateRequest("/account", "", "GET", new JObject());
        }

        /**
         * Returns the balance for an account
         * @param options optional parameters: symbol
         * @return JArray response, get individual balances by iterating over array: response.getJObject(index)
         */
        public JArray Balance(JObject options)
        {
            string postfix = CreatePostfix(options);
            return privateRequestArray("/balance", postfix, "GET", new JObject());
        }

        /**
         * Returns the deposit address which can be used to increase the account balance
         * @param symbol the crypto currency for which the address should be returned
         * @return JObject response, get address through response.getString("address")
         */
        public JObject DepositAssets(string symbol)
        {
            JObject options = new JObject();
            options.put("symbol", symbol);
            string postfix = CreatePostfix(options);
            return privateRequest("/deposit", postfix, "GET", new JObject());
        }

        /**
         * Creates a withdrawal to another address
         * @param symbol the crypto currency for which the withdrawal should be created
         * @param amount the amount which should be withdrawn
         * @param address The address to which the crypto should get sent
         * @param body optional parameters: paymentId, internal, addWithdrawalFee
         * @return JObject response, get success confirmation through response.getBoolean("success")
         */
        public JObject WithdrawAssets(string symbol, string amount, string address, JObject body)
        {
            body.put("symbol", symbol);
            body.put("amount", amount);
            body.put("address", address);
            return privateRequest("/withdrawal", "", "POST", body);
        }

        /**
         * Returns the entire deposit history for an account
         * @param options optional parameters: symbol, limit, start, end
         * @return JArray response, get individual deposits by iterating over the array: response.getJObject(index)
         */
        public JArray DepositHistory(JObject options)
        {
            string postfix = CreatePostfix(options);
            return privateRequestArray("/depositHistory", postfix, "GET", new JObject());
        }

        /**
         * Returns the entire withdrawal history for an account
         * @param options optional parameters: symbol, limit, start, end
         * @return JArray response, get individual withdrawals by iterating over the array: response.getJObject(index)
         */
        public JArray WithdrawalHistory(JObject options)
        {
            string postfix = CreatePostfix(options);
            return privateRequestArray("/withdrawalHistory", postfix, "GET", new JObject());
        }

        /**
         * Creates a websocket object
         * @return Websocket the object on which all websocket function can be called.
         */
        public Websocket NewWebsocket()
        {
            websocketObject = new Websocket();
            return websocketObject;
        }

        public class Websocket
        {
            public Websocket()
            {
                try
                {
                    final WebsocketClientEndpoint clientEndPoint = new WebsocketClientEndpoint(new URI(Bitvavo.this.wsUrl), Bitvavo.this);
                    clientEndPoint.addAuthenticateHandler(new WebsocketClientEndpoint.MessageHandler()
                    {
          public void handleMessage(JObject response)
                    {
                        if (response.has("authenticated"))
                        {
                            authenticated = true;
                            debugToConsole("We registered authenticated as true");
                        }
                    }
                });
                clientEndPoint.addMessageHandler(new WebsocketClientEndpoint.MessageHandler()
                {
          public void handleMessage(JObject response)
                {
                    errorToConsole("Unexpected message: " + response);
                }
            });
        ws = clientEndPoint;
        Book = new HashMap<string, object>();
        KeepAliveThread keepAliveThread = new KeepAliveThread();
            keepAliveThread.start();
        Bitvavo.this.keepAliveThread = keepAliveThread;
      }
      catch(Exception ex) {
        errorToConsole("Caught exception in websocket: " + ex);
    }
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
    if (getApiKey() == null)
    {
        errorToConsole("You forgot to set the key and secret, both are required for this functionality.");
    }
    else if (authenticated)
    {
        ws.sendMessage(options.toString());
    }
    else
    {
        try
        {
            TimeUnit.MILLISECONDS.sleep(50);
            DoSendPrivate(options);
        }
        catch (InterruptedException ex)
        {
            errorToConsole("Interrupted, aborting send.");
        }
    }
}

/**
 * Sets the callback for errors
 * @param msgHandler callback
 */
public void SetErrorCallback(WebsocketClientEndpoint.MessageHandler msgHandler)
{
    ws.addErrorHandler(msgHandler);
}

/**
* Returns the current time in unix timestamp (milliseconds since 1 jan 1970).
*@param msgHandler callback
* @return JObject response, get time through response.getJObject("response").getLong("time")
*/
public void Time(WebsocketClientEndpoint.MessageHandler msgHandler)
{
    ws.addTimeHandler(msgHandler);
    DoSendPublic(new JObject("{ action: getTime }"));
}

public void Markets(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addMarketsHandler(msgHandler);
            options.put("action", "getMarkets");
            DoSendPublic(options);
        }

        public void Assets(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addAssetsHandler(msgHandler);
            options.put("action", "getAssets");
            DoSendPublic(options);
        }


        public void Book(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addBookHandler(msgHandler);
            options.put("action", "getBook");
            options.put("market", market);
            DoSendPublic(options);
        }


        public void PublicTrades(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTradesHandler(msgHandler);
            options.put("action", "getTrades");
            options.put("market", market);
            DoSendPublic(options);
        }


        public void Candles(string market, string interval, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCandlesHandler(msgHandler);
            options.put("action", "getCandles");
            options.put("market", market);
            options.put("interval", interval);
            DoSendPublic(options);
        }


        public void Ticker24H(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTicker24hHandler(msgHandler);
            options.put("action", "getTicker24h");
            DoSendPublic(options);
        }


        public void TickerPrice(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTickerPriceHandler(msgHandler);
            options.put("action", "getTickerPrice");
            DoSendPublic(options);
        }


        public void TickerBook(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addTickerBookHandler(msgHandler);
            options.put("action", "getTickerBook");
            DoSendPublic(options);
        }


        public void PlaceOrder(string market, string side, string orderType, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addPlaceOrderHandler(msgHandler);
            body.put("market", market);
            body.put("side", side);
            body.put("orderType", orderType);
            body.put("action", "privateCreateOrder");
            DoSendPrivate(body);
        }


        public void GetOrder(string market, string orderId, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrderHandler(msgHandler);
            JObject options = new JObject();
            options.put("action", "privateGetOrder");
            options.put("market", market);
            options.put("orderId", orderId);
            DoSendPrivate(options);
        }


        public void UpdateOrder(string market, string orderId, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addUpdateOrderHandler(msgHandler);
            body.put("market", market);
            body.put("orderId", orderId);
            body.put("action", "privateUpdateOrder");
            DoSendPrivate(body);
        }


        public void CancelOrder(string market, string orderId, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCancelOrderHandler(msgHandler);
            JObject options = new JObject();
            options.put("action", "privateCancelOrder");
            options.put("market", market);
            options.put("orderId", orderId);
            DoSendPrivate(options);
        }


        public void GetOrders(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrdersHandler(msgHandler);
            options.put("action", "privateGetOrders");
            options.put("market", market);
            DoSendPrivate(options);
        }


        public void CancelOrders(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addCancelOrdersHandler(msgHandler);
            options.put("action", "privateCancelOrders");
            DoSendPrivate(options);
        }


        public void OrdersOpen(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetOrdersOpenHandler(msgHandler);
            options.put("action", "privateGetOrdersOpen");
            DoSendPrivate(options);
        }


        public void Trades(string market, JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addGetTradesHandler(msgHandler);
            options.put("action", "privateGetTrades");
            options.put("market", market);
            DoSendPrivate(options);
        }


        public void Account(WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addAccountHandler(msgHandler);
            JObject options = new JObject("{ action: privateGetAccount }");
            DoSendPrivate(options);
        }


        public void Balance(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addBalanceHandler(msgHandler);
            options.put("action", "privateGetBalance");
            DoSendPrivate(options);
        }


        public void DepositAssets(string symbol, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addDepositAssetsHandler(msgHandler);
            JObject options = new JObject("{ action: privateDepositAssets }");
            options.put("symbol", symbol);
            DoSendPrivate(options);
        }


        public void WithdrawAssets(string symbol, string amount, string address, JObject body, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addWithdrawAssetsHandler(msgHandler);
            body.put("action", "privateWithdrawAssets");
            body.put("symbol", symbol);
            body.put("amount", amount);
            body.put("address", address);
            DoSendPrivate(body);
        }


        public void DepositHistory(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addDepositHistoryHandler(msgHandler);
            options.put("action", "privateGetDepositHistory");
            DoSendPrivate(options);
        }


        public void WithdrawalHistory(JObject options, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addWithdrawalHistoryHandler(msgHandler);
            options.put("action", "privateGetWithdrawalHistory");
            DoSendPrivate(options);
        }


        public void SubscriptionTicker(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTickerHandler(market, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "ticker");
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionTicker = true;
            if (optionsSubscriptionTicker == null)
            {
                optionsSubscriptionTicker = new JObject();
            }
            optionsSubscriptionTicker.put(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionTicker24H(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTicker24hHandler(market, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "ticker24h");
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionTicker24h = true;
            if (optionsSubscriptionTicker24h == null)
            {
                optionsSubscriptionTicker24h = new JObject();
            }
            optionsSubscriptionTicker24h.put(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionAccount(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionAccountHandler(market, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "account");
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionAccount = true;
            if (optionsSubscriptionAccount == null)
            {
                optionsSubscriptionAccount = new JObject();
            }
            optionsSubscriptionAccount.put(market, options);
            DoSendPrivate(options);
        }

        public void SubscriptionCandles(string market, string interval, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionCandlesHandler(market, interval, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "candles");
            subOptions.put("interval", new string[] { interval });
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionCandles = true;
            JObject intervalIndex = new JObject();
            intervalIndex.put(interval, options);
            if (optionsSubscriptionCandles == null)
            {
                optionsSubscriptionCandles = new JObject();
            }
            optionsSubscriptionCandles.put(market, intervalIndex);
            DoSendPublic(options);
        }


        public void SubscriptionTrades(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionTradesHandler(market, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "trades");
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionTrades = true;
            if (optionsSubscriptionTrades == null)
            {
                optionsSubscriptionTrades = new JObject();
            }
            optionsSubscriptionTrades.put(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionBookUpdate(string market, WebsocketClientEndpoint.MessageHandler msgHandler)
        {
            ws.addSubscriptionBookUpdateHandler(market, msgHandler);
            JObject options = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "book");
            subOptions.put("markets", new string[] { market });
            options.put("action", "subscribe");
            options.put("channels", new JObject[] { subOptions });
            activatedSubscriptionBookUpdate = true;
            if (optionsSubscriptionBookUpdate == null)
            {
                optionsSubscriptionBookUpdate = new JObject();
            }
            optionsSubscriptionBookUpdate.put(market, options);
            DoSendPublic(options);
        }


        public void SubscriptionBook(string market, WebsocketClientEndpoint.BookHandler msgHandler)
        {
            ws.keepBookCopy = true;
            Map<string, object> bidsAsks = new HashMap<string, object>();
            bidsAsks.put("bids", new ArrayList<ArrayList<Float>>());
            bidsAsks.put("asks", new ArrayList<ArrayList<Float>>());

            Book.put(market, bidsAsks);
            ws.addSubscriptionBookHandler(market, msgHandler);
            JObject options = new JObject();
            options.put("action", "getBook");
            options.put("market", market);
            activatedSubscriptionBook = true;
            if (optionsSubscriptionBookFirst == null)
            {
                optionsSubscriptionBookFirst = new JObject();
            }
            optionsSubscriptionBookFirst.put(market, options);
            DoSendPublic(options);

            JObject secondOptions = new JObject();
            JObject subOptions = new JObject();
            subOptions.put("name", "book");
            subOptions.put("markets", new string[] { market });
            secondOptions.put("action", "subscribe");
            secondOptions.put("channels", new JObject[] { subOptions });
            if (optionsSubscriptionBookSecond == null)
            {
                optionsSubscriptionBookSecond = new JObject();
            }
            optionsSubscriptionBookSecond.put(market, secondOptions);
            DoSendPublic(secondOptions);
        }
    }
}
