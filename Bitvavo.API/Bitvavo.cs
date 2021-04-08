namespace Bitvavo.API
{
    using System;
    using System.IO;
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
        /// <param name="restUrl">The rest URL.</param>
        /// <param name="webSocketUrl">The web socket URL.</param>
        /// <param name="debugging">if set to <c>true</c> [debugging].</param>
        public Bitvavo(string apiKey, string apiSecret, int accessWindow, string restUrl, string webSocketUrl, bool debugging)
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
        public JArray PrivateRequestArray(String urlEndpoint, String urlParams, String method, JObject body)
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
    }
}
