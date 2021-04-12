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
                using var client = new HttpClient { BaseAddress = ApiUri };
                var bodyString = jsonBody.ToString(Formatting.None);
                if (!string.IsNullOrEmpty(ApiKey) && !string.IsNullOrEmpty(ApiSecret))
                {
                    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var signature = CreateSignature(timestamp, method.ToString(), (urlString), bodyString);
                    client.DefaultRequestHeaders.Add("Bitvavo-Access-Key", ApiKey);
                    client.DefaultRequestHeaders.Add("Bitvavo-Access-Signature", signature);
                    client.DefaultRequestHeaders.Add("Bitvavo-Access-Timestamp", timestamp.ToString());
                    client.DefaultRequestHeaders.Add("Bitvavo-Access-Window", AccessWindow.ToString());
                }

                var request = new HttpRequestMessage(method, urlString)
                {
                    Content = string.IsNullOrEmpty(bodyString)
                                  ? new StringContent("")
                                  : new StringContent(bodyString, Encoding.UTF8, "application/json"),
                };

                var response = client.SendAsync(request).Result;
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
    }
}
