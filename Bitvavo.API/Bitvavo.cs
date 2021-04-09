namespace Bitvavo.API
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Net.WebSockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;

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
        /// Webs the request.
        /// </summary>
        /// <param name="urlString">The URL string.</param>
        /// <param name="method">The method.</param>
        /// <returns></returns>
        private string WebRequest(string urlString, HttpMethod method)
        {
            if (!string.IsNullOrEmpty(ApiKey) && !string.IsNullOrEmpty(ApiSecret))
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var signature = CreateSignature(timestamp, method.ToString(), (urlString), string.Empty);
                Client.DefaultRequestHeaders.Add("Bitvavo-Access-Key", ApiKey);
                Client.DefaultRequestHeaders.Add("Bitvavo-Access-Signature", signature);
                Client.DefaultRequestHeaders.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                Client.DefaultRequestHeaders.Add("Bitvavo-Access-Window", AccessWindow.ToString());
            }

            var request = new HttpRequestMessage(method, urlString);
            if (request.Content == null) { request.Content = new StringContent(""); }
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var response = Client.SendAsync(request).Result;
            return response.Content.ReadAsStringAsync().Result;
        }

        /*/// <summary>
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
                    UpdateRateLimit(myHttpWebResponse.Headers);
                }

                var responseFromServer = reader.ReadToEnd();
                var response = JObject.Parse(responseFromServer);
                if (responseFromServer.Contains("errorCode"))
                {
                    ErrorRateLimit(response);
                }
                return response;
            }
            catch (Exception ex)
            {
                ErrorToConsole("Caught exception in PrivateRequest " + ex);
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
                ErrorToConsole("Caught exception in PrivateRequest " + ex);
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
        }*/

        /// <summary>
        /// Times this instance.
        /// </summary>
        /// <returns></returns>
        public string Time()
        {
            return WebRequest($"{ApiUri}/time", HttpMethod.Get);
        }

        /// <summary>
        /// Markets the specified options.
        /// </summary>
        /// <param name="market">The market.</param>
        /// <returns></returns>
        public string Markets(string market)
        {
            var query = string.Empty;
            AddQuery(ref query, nameof(market), market);
            return WebRequest($"{ApiUri}/markets{query}", HttpMethod.Get);
        }

        /*/// <summary>
        /// Assetses the specified options.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        public JArray Assets(JObject options)
        {
            var postfix = CreatePostfix(options);
            return options.ContainsKey("symbol")
                       ? new JArray(PublicRequest((ApiUri + "/assets" + postfix), "GET", new JObject()))
                       : PublicRequestArray((ApiUri + "/assets" + postfix), "GET", new JObject());
        }

        /**
         * Returns the book for a certain market
         * @param market Specifies the market for which the book should be returned.
         * @param options optional parameters: depth
         * @return JObject response, get bids through response.getJArray("bids"), asks through response.getJArray("asks")
         #1#
        public JObject Book(string market, JObject options)
        {
            var postfix = CreatePostfix(options);
            return PublicRequest((ApiUri + "/" + market + "/book" + postfix), "GET", new JObject());
        }

        /**
         * Returns the trades for a specific market
         * @param market Specifies the market for which trades should be returned
         * @param options optional parameters: limit, start, end, tradeIdFrom, tradeIdTo
         * @return JArray response, iterate over array to get individual trades response.getJObject(index)
         #1#
        public JArray PublicTrades(string market, JObject options)
        {
            var postfix = CreatePostfix(options);
            return PublicRequestArray((ApiUri + "/" + market + "/trades" + postfix), "GET", new JObject());
        }

        /**
         *  Returns the candles for a specific market
         * @param market market for which the candles should be returned
         * @param interval interval on which the candles should be returned
         * @param options optional parameters: limit, start, end
         * @return JArray response, get individual candles through response.getJArray(index)
         #1#
        public JArray Candles(string market, string interval, JObject options)
        {
            options.Add("interval", interval);
            var postfix = CreatePostfix(options);
            return PublicRequestArray((ApiUri + "/" + market + "/candles" + postfix), "GET", new JObject());
        }

        /**
         * Returns the ticker price
         * @param options optional parameters: market
         * @return JArray response, get individual prices by iterating over array: response.getJObject(index)
         #1#
        public JArray TickerPrice(JObject options)
        {
            var postfix = CreatePostfix(options);
            if (options.ContainsKey("market"))
            {
                var returnArray = new JArray();
                returnArray.Add(PublicRequest((ApiUri + "/ticker/price" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((ApiUri + "/ticker/price" + postfix), "GET", new JObject());
            }
        }

        /**
         * Return the book ticker
         * @param options optional parameters: market
         * @return JArray response, get individual books by iterating over array: response.getJObject(index)
         #1#
        public JArray TickerBook(JObject options)
        {
            var postfix = CreatePostfix(options);
            if (options.ContainsKey("market"))
            {
                var returnArray = new JArray();
                returnArray.Add(PublicRequest((ApiUri + "/ticker/book" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((ApiUri + "/ticker/book" + postfix), "GET", new JObject());
            }
        }

        /**
         * Return the 24 hour ticker
         * @param options optional parameters: market
         * @return JArray response, get individual 24 hour prices by iterating over array: response.getJObject(index)
         #1#
        public JArray Ticker24H(JObject options)
        {
            var postfix = CreatePostfix(options);
            if (options.ContainsKey("market"))
            {
                var returnArray = new JArray();
                returnArray.Add(PublicRequest((ApiUri + "/ticker/24h" + postfix), "GET", new JObject()));
                return returnArray;
            }
            else
            {
                return PublicRequestArray((ApiUri + "/ticker/24h" + postfix), "GET", new JObject());
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
         #1#
        public JObject PlaceOrder(string market, string side, string orderType, JObject body)
        {
            body.Add("market", market);
            body.Add("side", side);
            body.Add("orderType", orderType);
            return PrivateRequest("/order", "", "POST", body);
        }

        /**
         * Returns a specific order
         * @param market the market the order resides on
         * @param orderId the id of the order
         * @return JObject response, get status of the order through response.getString("status")
         #1#
        public JObject GetOrder(string market, string orderId)
        {
            var options = new JObject();
            options.Add("market", market);
            options.Add("orderId", orderId);
            var postfix = CreatePostfix(options);
            return PrivateRequest("/order", postfix, "GET", new JObject());
        }

        /**
         * Updates an order
         * @param market the market the order resides on
         * @param orderId the id of the order which should be updated
         * @param body optional body parameters: limit:(amount, amountRemaining, price, timeInForce, selfTradePrevention, postOnly)
         *                           untriggered stopLoss/takeProfit:(amount, amountQuote, disableMarketProtection, triggerType, triggerReference, triggerAmount)
         *                                       stopLossLimit/takeProfitLimit: (amount, price, postOnly, triggerType, triggerReference, triggerAmount)
         * @return JObject response, get status of the order through response.getString("status")
         #1#
        public JObject UpdateOrder(string market, string orderId, JObject body)
        {
            body.Add("market", market);
            body.Add("orderId", orderId);
            return PrivateRequest("/order", "", "PUT", body);
        }

        /**
         * Cancel an order
         * @param market the market the order resides on
         * @param orderId the id of the order which should be cancelled
         * @return JObject response, get the id of the order which was cancelled through response.getString("orderId")
         #1#
        public JObject CancelOrder(string market, string orderId)
        {
            var options = new JObject();
            options.Add("market", market);
            options.Add("orderId", orderId);
            var postfix = CreatePostfix(options);
            return PrivateRequest("/order", postfix, "DELETE", new JObject());
        }

        /**
         * Returns multiple orders for a specific market
         * @param market the market for which orders should be returned
         * @param options optional parameters: limit, start, end, orderIdFrom, orderIdTo
         * @return JArray response, get individual orders by iterating over array: response.getJObject(index)
         #1#
        public JArray GetOrders(string market, JObject options)
        {
            options.Add("market", market);
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/orders", postfix, "GET", new JObject());
        }

        /**
         * Cancel multiple orders at once, if no market is specified all orders will be canceled
         * @param options optional parameters: market
         * @return JArray response, get individual cancelled orderId's by iterating over array: response.getJObject(index).getString("orderId")
         #1#
        public JArray CancelOrders(JObject options)
        {
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/orders", postfix, "DELETE", new JObject());
        }

        /**
         * Returns all open orders for an account
         * @param options optional parameters: market
         * @return JArray response, get individual orders by iterating over array: response.getJObject(index)
         #1#
        public JArray OrdersOpen(JObject options)
        {
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/ordersOpen", postfix, "GET", new JObject());
        }

        /**
         * Returns all trades for a specific market
         * @param market the market for which trades should be returned
         * @param options optional parameters: limit, start, end, tradeIdFrom, tradeIdTo
         * @return JArray trades, get individual trades by iterating over array: response.getJObject(index)
         #1#
        public JArray Trades(string market, JObject options)
        {
            options.Add("market", market);
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/trades", postfix, "GET", new JObject());
        }

        /**
         * Return the fee tier for an account
         * @return JObject response, get taker fee through: response.getJObject("fees").getString("taker")
         #1#
        public JObject Account()
        {
            return PrivateRequest("/account", "", "GET", new JObject());
        }

        /**
         * Returns the balance for an account
         * @param options optional parameters: symbol
         * @return JArray response, get individual balances by iterating over array: response.getJObject(index)
         #1#
        public JArray Balance(JObject options)
        {
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/balance", postfix, "GET", new JObject());
        }

        /**
         * Returns the deposit address which can be used to increase the account balance
         * @param symbol the crypto currency for which the address should be returned
         * @return JObject response, get address through response.getString("address")
         #1#
        public JObject DepositAssets(string symbol)
        {
            var options = new JObject();
            options.Add("symbol", symbol);
            var postfix = CreatePostfix(options);
            return PrivateRequest("/deposit", postfix, "GET", new JObject());
        }

        /**
         * Creates a withdrawal to another address
         * @param symbol the crypto currency for which the withdrawal should be created
         * @param amount the amount which should be withdrawn
         * @param address The address to which the crypto should get sent
         * @param body optional parameters: paymentId, internal, addWithdrawalFee
         * @return JObject response, get success confirmation through response.getBoolean("success")
         #1#
        public JObject WithdrawAssets(string symbol, string amount, string address, JObject body)
        {
            body.Add("symbol", symbol);
            body.Add("amount", amount);
            body.Add("address", address);
            return PrivateRequest("/withdrawal", "", "POST", body);
        }

        /**
         * Returns the entire deposit history for an account
         * @param options optional parameters: symbol, limit, start, end
         * @return JArray response, get individual deposits by iterating over the array: response.getJObject(index)
         #1#
        public JArray DepositHistory(JObject options)
        {
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/depositHistory", postfix, "GET", new JObject());
        }

        /**
         * Returns the entire withdrawal history for an account
         * @param options optional parameters: symbol, limit, start, end
         * @return JArray response, get individual withdrawals by iterating over the array: response.getJObject(index)
         #1#
        public JArray WithdrawalHistory(JObject options)
        {
            var postfix = CreatePostfix(options);
            return PrivateRequestArray("/withdrawalHistory", postfix, "GET", new JObject());
        }

        /**
         * Creates a websocket object
         * @return Websocket the object on which all websocket function can be called.
         #1#
        public Websocket NewWebsocket()
        {
            websocketObject = new Websocket();
            return websocketObject;
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
        }*/
    }
}
