using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

using Newtonsoft.Json;

namespace NdisFilter
{
    internal class Settings
    {
        public static Settings Default { get; internal set; } = JsonConvert.DeserializeObject<Settings>(File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "NdisFilter.json")));

        private Settings() { }

        [JsonProperty("Buffer")]
        public int Buffer { get; set; }

        [JsonProperty("Port")]
        public ushort Port { get; set; }

        [JsonProperty("Allow")]
        private string[] _allows
        {
            get => Allows?.Select(_ => _.ToString()).ToArray();
            set
            {
                Allows = value?.Where(_ => IPAddress.TryParse(_, out var ip)).Select(_ => IPAddress.Parse(_)).ToArray();
            }
        }

        [JsonIgnore]
        public IPAddress[] Allows { get; set; }
    }
}