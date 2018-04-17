using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using XENA.API.Samples.Cryptography;

namespace XENA.API.Samples.Auth
{
    public class AuthChannel
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
        }
    }
}
