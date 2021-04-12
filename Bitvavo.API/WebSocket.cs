namespace Bitvavo.API
{
    using System;
    using System.IO;
    using System.Net.WebSockets;
    using System.Threading;
    using System.Threading.Tasks;

    public class WebSocket
    {
        private readonly Uri SocketUri = new Uri("wss://ws.bitvavo.com/v2/");
        private readonly string ApiKey = "";
        private readonly string ApiSecret = "";
        private readonly int AccessWindow = 10000;

        private Bitvavo Bitvavo { get; }

        public WebSocket(string apiKey, string apiSecret, int accessWindow, string socketUri, Bitvavo bitvavo)
        {
            ApiKey = !string.IsNullOrEmpty(apiKey) ? apiKey : ApiKey;
            ApiSecret = !string.IsNullOrEmpty(apiSecret) ? apiSecret : ApiSecret;
            AccessWindow = accessWindow != 0 ? accessWindow : AccessWindow;
            SocketUri = !string.IsNullOrEmpty(socketUri) ? new Uri(socketUri) : SocketUri;
            Bitvavo = bitvavo;
        }

        /// <summary>
        /// Connects the asynchronous.
        /// </summary>
        /// <param name="url">The URL.</param>
        public async Task ConnectAsync(string url)
        {
            if (Ws != null)
            {
                if (Ws.State == WebSocketState.Open) return;
                else Ws.Dispose();
            }
            Ws = new ClientWebSocket();
            if (Cts != null) Cts.Dispose();
            Cts = new CancellationTokenSource();
            await Ws.ConnectAsync(new Uri(url), Cts.Token);
            await Task.Factory.StartNew(ReceiveLoop, Cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        /// <summary>
        /// Disconnects the asynchronous.
        /// </summary>
        public async Task DisconnectAsync()
        {
            if (Ws is null) return;
            // TODO: requests cleanup code, sub-protocol dependent.
            if (Ws.State == WebSocketState.Open)
            {
                Cts.CancelAfter(TimeSpan.FromSeconds(2));
                await Ws.CloseOutputAsync(WebSocketCloseStatus.Empty, "", CancellationToken.None);
                await Ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
            }
            Ws.Dispose();
            Ws = null;
            Cts.Dispose();
            Cts = null;
        }

        /// <summary>
        /// Receives the loop.
        /// </summary>
        private async Task ReceiveLoop()
        {
            var loopToken = Cts.Token;
            MemoryStream outputStream = null;
            WebSocketReceiveResult receiveResult = null;
            var buffer = new byte[ReceiveBufferSize];
            try
            {
                while (!loopToken.IsCancellationRequested)
                {
                    outputStream = new MemoryStream(ReceiveBufferSize);
                    do
                    {
                        receiveResult = await Ws.ReceiveAsync(buffer, Cts.Token);
                        if (receiveResult.MessageType != WebSocketMessageType.Close)
                            outputStream.Write(buffer, 0, receiveResult.Count);
                    }
                    while (!receiveResult.EndOfMessage);
                    if (receiveResult.MessageType == WebSocketMessageType.Close) break;
                    outputStream.Position = 0;
                    ResponseReceived(outputStream);
                }
            }
            catch (TaskCanceledException) { }
            finally
            {
                outputStream?.Dispose();
            }
        }

        private async Task<ResponseType> SendMessageAsync<TRequestType>(TRequestType message)
        {
            // TODO: handle serializing requests and deserializing responses, handle matching responses to the requests.
        }

        private void ResponseReceived(Stream inputStream)
        {
            // TODO: handle deserializing responses and matching them to the requests.
            // IMPORTANT: DON'T FORGET TO DISPOSE THE inputStream!
        }

        public void Dispose() => DisconnectAsync().Wait();

        private ClientWebSocket Ws;
        private CancellationTokenSource Cts;
    }
}