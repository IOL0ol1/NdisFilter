using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

using NdisApi;

using NdisFilter.Core;

using NLog;

using PacketDotNet;

using SharpPcap;
using SharpPcap.LibPcap;

namespace NdisFilter.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var file = @"C:\Users\IOL0ol1\Desktop\testdata\pb.pcapng"; //args[0];
            INetFilter filter = new NetFilter(new IPEndPoint[0], LogManager.GetCurrentClassLogger());
            List<RawPacket> toAdapter = new List<RawPacket>(64);
            List<RawPacket> toMstcp = new List<RawPacket>(64);
            Dictionary<IPAddress, List<RawPacket>> historyPacket = new Dictionary<IPAddress, List<RawPacket>>();

            var dev = new CaptureFileReaderDevice(file);
            try
            {
                dev.Open();
                RawCapture packet;
                long lastProgress = 0;
                long position = 0;
                while ((packet = dev.GetNextPacket()) != null)
                {
                    var host = IPAddress.Parse("31.204.145.45");
                    if (packet.GetPacket().Extract<IPv4Packet>() is IPv4Packet ipv4Packet
                        && ipv4Packet.Extract<UdpPacket>() is UdpPacket udpPacket
                        && (udpPacket.DestinationPort == 25660 || udpPacket.SourcePort == 25660)
                        )
                    {
                        RawPacket rawPacket = new RawPacket { Data = packet.Data, DeviceFlags = ipv4Packet.SourceAddress.Equals(host) ? PACKET_FLAG.PACKET_FLAG_ON_SEND : PACKET_FLAG.PACKET_FLAG_ON_RECEIVE };
                        filter.Run(new[] { rawPacket }, toMstcp, toAdapter);

                        foreach (var item in toMstcp)
                        {
                            var p = Packet.ParsePacket(LinkLayers.Ethernet, item.Data).Extract<IPv4Packet>();
                            var src = p.SourceAddress;
                            if (historyPacket.ContainsKey(src))
                                historyPacket[src].Add(item);
                            else
                            {
                                Console.WriteLine($"{src} => {p.DestinationAddress}");
                                historyPacket.Add(src, new List<RawPacket>());
                            }
                        }
                    }
                    position += packet.Data.Length;
                    var progress = position * 100 / dev.FileSize;
                    if (lastProgress != progress)
                        Console.WriteLine($"Progress : {progress * 20 / 17}");
                    lastProgress = progress;

                }
                foreach (var item in historyPacket.OrderBy(_ => BitConverter.ToUInt32(_.Key.GetAddressBytes(), 0)))
                {
                    Console.WriteLine($"{item.Key} {item.Value.Count}");
                }

            }
            finally
            {
                dev.Close();
            }
        }
    }
}
