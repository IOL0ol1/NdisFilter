using System;
using System.Collections.Generic;
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
        private HashSet<IPEndPoint> _allows;
        private IPEndPoint[] _config;
        private ILogger _logger;

        private Dictionary<IPEndPoint, List<RawPacket>> _historyPacket = new Dictionary<IPEndPoint, List<RawPacket>>();



        public NetFilter(IPEndPoint[] allows = null, ILogger logger = null)
        {
            _config = allows ?? new IPEndPoint[0];
            _allows = new HashSet<IPEndPoint>(allows);
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
            var ticks = rawPackets.Select(_ => _.Data[43] << 8 | _.Data[42]).ToList();
            var last = ticks[ticks.Count - 1];
            if (last < 0x8000) return false;
            if (ticks.Count < 2) return true;
            var prev = ticks[ticks.Count - 2];
            var delta = prev > 0xFE00 && last < 0x81FF ? 0x7FFF + last - prev : last - prev;
            return 0 < delta && delta < 160;
        }

        public void Run(IReadOnlyList<RawPacket> rawPackets, List<RawPacket> toMstcp, List<RawPacket> toAdapter)
        {
            foreach (var packet in rawPackets)
            {

                if (Packet.ParsePacket(LinkLayers.Ethernet, packet.Data) is EthernetPacket ethernet && ethernet.PayloadPacket is IPv4Packet ipPacket && ipPacket.PayloadPacket is UdpPacket udpPacket)
                {
                    // Depending on the packet direction insert it to the appropriate list
                    if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE)
                    {
                        var srcEndPoint = new IPEndPoint(ipPacket.SourceAddress, udpPacket.SourcePort);
                        if (_allows.Contains(srcEndPoint) || _allows.Contains(new IPEndPoint(ipPacket.SourceAddress, 0)))
                        {
                            toMstcp.Add(packet);
                            continue;
                        }
                        /// Intercepts the first data of the new IP, 
                        /// and when the second data arrives, if the check passes, 
                        /// sends both data to forward upwards the network stack at the same time.
                        if (_historyPacket.TryGetValue(srcEndPoint, out var packets))
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
                            _historyPacket[srcEndPoint] = new List<RawPacket>(6) { packet };
                        }
                    }
                    else
                    {
                        if (BitConverter.ToUInt32(ethernet.Bytes, 42) == 0x2079656B) // pb data
                        {
                            _logger?.Info(ethernet);
                            _allows.Add(new IPEndPoint(ipPacket.DestinationAddress, udpPacket.DestinationPort));
                        }
                        toAdapter.Add(packet);
                    }
                }
            }
        }

    }
}
