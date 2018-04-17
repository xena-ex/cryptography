using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace XENA.TradingApi.Channels
{
    public class Logon
    {        
        [JsonProperty("35")]
        public string Message => "A";
        [JsonProperty("1")]
        public List<long> Accounts { get; set; }
        [JsonProperty("553")]
        public string Username { get; set; }
        [JsonProperty("52")]
        public long SendingTime { get; set; }
        [JsonProperty("96")]
        public string RawData { get; set; }
        [JsonProperty("554")]
        public string Password { get; set; }
    }
}
