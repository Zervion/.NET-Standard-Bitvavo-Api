﻿namespace Bitvavo.Example.Example
{
    using System;

    using Bitvavo.API;

    public class TestApi
    {
        public TestApi()
        {
            var bitvavo = new Bitvavo("", "", 10000, "https://api.bitvavo.com/v2", "wss://ws.bitvavo.com/v2/", false);
            TestRest(bitvavo);
            TestWebsocket(bitvavo);
        }

        /// <summary>
        /// Tests the rest.
        /// </summary>
        public static void TestRest(Bitvavo bitvavo)
        {
            var remaining = bitvavo.GetRemainingLimit();
            Console.WriteLine("remaining limit is " + remaining);

            var response = bitvavo.Time();
            Console.WriteLine("Time => " + response);

            response = bitvavo.Markets("");
            Console.WriteLine("Markets => " + response);

            // response = bitvavo.markets(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.assets(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // System.out.println(bitvavo.book("BTC-EUR", new JSONObject()).toString(2));

            // response = bitvavo.publicTrades("BTC-EUR", new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // JSONArray candles = bitvavo.candles("BTC-EUR", "1h", new JSONObject());
            // for(int i = 0; i < candles.length(); i ++) {
            //   System.out.println(candles.getJSONArray(i).toString(2));
            // }

            // response = bitvavo.tickerPrice(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.tickerBook(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.ticker24h(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // System.out.println(bitvavo.placeOrder("BTC-EUR", "sell", "limit", new JSONObject("{ amount: 0.1, price: 4000 }")).toString(2));

            // System.out.println(bitvavo.placeOrder("BTC-EUR", "sell", "stopLoss", new JSONObject("{ amount: 0.1, triggerType: price, triggerReference: lastTrade, triggerAmount: 5000 }")).toString(2));

            // System.out.println(bitvavo.getOrder("BTC-EUR", "afa9da1c-edb9-4245-9271-3549147845a1").toString(2));

            // System.out.println(bitvavo.updateOrder("BTC-EUR", "afa9da1c-edb9-4245-9271-3549147845a1", new JSONObject("{ amount: 0.2 }")).toString(2));

            // System.out.println(bitvavo.cancelOrder("BTC-EUR", "afa9da1c-edb9-4245-9271-3549147845a1").toString(2));

            // response = bitvavo.getOrders("BTC-EUR", new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.cancelOrders(new JSONObject("{ market: BTC-EUR }"));
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.ordersOpen(new JSONObject("{ market: BTC-EUR }"));
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.trades("BTC-EUR", new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }


            // System.out.println(bitvavo.account().toString(2));

            // response = bitvavo.balance(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // System.out.println(bitvavo.depositAssets("BTC").toString(2));

            // System.out.println(bitvavo.withdrawAssets("BTC", "1", "BitcoinAddress", new JSONObject()).toString(2));

            // response = bitvavo.depositHistory(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }

            // response = bitvavo.withdrawalHistory(new JSONObject());
            // for(int i = 0; i < response.length(); i ++) {
            //   System.out.println(response.getJSONObject(i).toString(2));
            // }
        }

        /// <summary>
        /// Tests the websocket.
        /// </summary>
        public static void TestWebsocket(Bitvavo bitvavo)
        {
            // ws.markets(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.assets(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.book("BTC-EUR", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.publicTrades("BTC-EUR", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.candles("BTC-EUR", "1h", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONArray(i).toString(2));
            //     }
            //   }
            // });

            // ws.ticker24h(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.tickerPrice(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.tickerBook(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.placeOrder("BTC-EUR", "sell", "limit", new JSONObject("{ amount: 1.2, price: 6000 }"), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.updateOrder("BTC-EUR", "8653b765-f6ce-44ad-b474-8cf56bd4469f", new JSONObject("{ amount: 1.4 }"), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.getOrder("BTC-EUR", "8653b765-f6ce-44ad-b474-8cf56bd4469f", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.cancelOrder("BTC-EUR", "8653b765-f6ce-44ad-b474-8cf56bd4469f", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.getOrders("BTC-EUR", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.cancelOrders(new JSONObject("{ market: BTC-EUR }"), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.ordersOpen(new JSONObject("{ market: BTC-EUR }"), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.trades("BTC-EUR", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.account(new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONObject response = responseObject.getJSONObject("response");
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.balance(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.depositAssets("BTC", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.withdrawAssets("BTC", "1", "BitcoinAddress", new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     System.out.println(responseObject.getJSONObject("response").toString(2));
            //   }
            // });

            // ws.depositHistory(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.withdrawalHistory(new JSONObject(), new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject responseObject) {
            //     JSONArray response = responseObject.getJSONArray("response");
            //     for (int i = 0; i < response.length(); i ++) {
            //       System.out.println(response.getJSONObject(i).toString(2));
            //     }
            //   }
            // });

            // ws.subscriptionTicker("BTC-EUR", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionTicker24h("BTC-EUR", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionAccount("BTC-EUR", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionCandles("BTC-EUR", "1h", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionTrades("BTC-EUR", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionBookUpdate("BTC-EUR", new WebsocketClientEndpoint.MessageHandler() {
            //   public void handleMessage(JSONObject response) {
            //     System.out.println(response.toString(2));
            //   }
            // });

            // ws.subscriptionBook("BTC-EUR", new WebsocketClientEndpoint.BookHandler() {
            //   public void handleBook(Map<String, Object> book) {
            //     List<List<String>> bids = (List<List<String>>)book.get("bids");
            //     List<List<String>> asks = (List<List<String>>)book.get("asks");
            //     String nonce = (String)book.get("nonce");
            //     System.out.println(book);
            //   }
            // });

            // The following function can be used to close the socket, callbacks will no longer be called.
            // ws.close()
        }
    }
}
