using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using GenericWebSocketClient.Channels;
using XENA.TradingApi.Cryptography;

namespace XENA.TradingApi.Channels
{
    public class AuthChannel: BaseChannel
    {
        Logon _logon;

        public AuthChannel(List<long> accounts, string apiKeyId, string apiSecret)
        {
            _logon = new Logon { Accounts = accounts, Username = apiKeyId };

            var nonce = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds() * 1000000;
            var authPayload = String.Format("AUTH{0}", nonce);
            var signature = XENASignature.Sign(apiSecret, authPayload);
            _logon.SendingTime = nonce;
            _logon.RawData = authPayload;
            _logon.Password = signature;

            AwaitableSubscribeResponseMessage = new LoggedOn();
        }

        public override string Id { get => "auth"; protected set {} }

        public override string Name => "auth";

        public override object SubscribeMessage => _logon;

        public override AwaitableSubscribeResponseMessage AwaitableSubscribeResponseMessage { get; } // TODO

        public override void OnMessage(object msg)
        {
            throw new NotImplementedException();
        }
    }
}
