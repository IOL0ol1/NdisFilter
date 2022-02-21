using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;

using NdisApi;

using NLog;

using PacketDotNet;

namespace NdisFilter.Core
{
    public interface INetFilter
    {
        void Init();

        void Run(IReadOnlyList<RawPacket> rawPackets, List<RawPacket> toMstcp, List<RawPacket> toAdapter);
    }

    public class NullFilter : INetFilter
    {
        public void Init()
        {

        }

        public void Run(IReadOnlyList<RawPacket> rawPackets, List<RawPacket> toMstcp, List<RawPacket> toAdapter)
        {
            foreach (var rawPacket in rawPackets)
            {
                if (rawPacket.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE)
                    toMstcp.Add(rawPacket);
                else
                    toAdapter.Add(rawPacket);
            }
        }
    }

    public class NetFilter : INetFilter
    {
        private HashSet<IPAddress> _allows;
        private IPAddress[] _config;
        private ILogger _logger;

        private Dictionary<IPAddress, List<RawPacket>> _historyPacket = new Dictionary<IPAddress, List<RawPacket>>();



        public NetFilter(IPAddress[] allows = null, ILogger logger = null)
        {
            _config = allows ?? new IPAddress[0];
            _allows = new HashSet<IPAddress>(allows);
            _logger = logger;
        }

        public void Init()
        {
            _historyPacket.Clear();
            _allows.Clear();
            foreach (var item in _config)
            {
                _allows.Add(item);
            }
        }

        /// <summary>
        /// check data id and delta of id
        /// </summary>
        /// <param name="rawPackets"></param>
        /// <returns></returns>
        private bool CheckPackets(List<RawPacket> rawPackets)
        {
            var ticks = rawPackets.Select(_ => _.Data[43] << 8 | _.Data[42]).ToArray();
            if (rawPackets.First().Data.Length > 600) return false;
            var last = ticks[ticks.Length - 1];
            if (last < 0x8000) return false;
            if (ticks.Length < 2) return true;
            var prev = ticks[ticks.Length - 2];
            var delta = prev > 0xFF00 && last < 0x80FF ? 0x7FFF + last - prev : last - prev;
            return 0 < delta && delta < 160;
        }

        public void Run(IReadOnlyList<RawPacket> rawPackets, List<RawPacket> toMstcp, List<RawPacket> toAdapter)
        {
            foreach (var packet in rawPackets)
            {

                if (Packet.ParsePacket(LinkLayers.Ethernet, packet.Data) is EthernetPacket ethernet && ethernet.PayloadPacket is IPv4Packet ipPacket)
                {
                    // Depending on the packet direction insert it to the appropriate list
                    if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE)
                    {
                        var srcAddress = ipPacket.SourceAddress;
                        if (_allows.Contains(srcAddress))
                        {
                            toMstcp.Add(packet);
                            continue;
                        }
                        /// Intercepts the first data of the new IP, 
                        /// and when the second data arrives, if the check passes, 
                        /// sends both data to forward upwards the network stack at the same time.
                        if (_historyPacket.TryGetValue(srcAddress, out var packets))
                        {
                            if (packets.Count != 0)
                            {
                                if (packets.Count < 5)
                                {
                                    packets.Add(packet);
                                    if (!CheckPackets(packets))
                                    {
                                        packets.Clear();
                                    }
                                    else if (packets.Count == 2)
                                    {
                                        toMstcp.Add(packets[0]);
                                        toMstcp.Add(packets[1]);
                                    }
                                    else if (packets.Count > 2)
                                    {
                                        toMstcp.Add(packet);
                                    }
                                }
                                else
                                {
                                    toMstcp.Add(packet);
                                }
                            }
                        }
                        else
                        {
                            _historyPacket[srcAddress] = new List<RawPacket>(6) { packet };
                        }
                    }
                    else
                    {
                        _allows.Add(ipPacket.DestinationAddress);
                        toAdapter.Add(packet);
                    }
                }
            }
        }

    }
}
