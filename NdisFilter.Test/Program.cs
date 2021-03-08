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
            var file = @"C:\Users\IOL0ol1\Desktop\=\testdata\output_00041_20210301143359.pcapng"; //args[0];
            INetFilter filter = new NetFilter(new IPAddress[0], LogManager.GetCurrentClassLogger());
            List<RawPacket> toAdapter = new List<RawPacket>(64);
            List<RawPacket> toMstcp = new List<RawPacket>(64);
            Dictionary<IPAddress, List<RawPacket>> historyPacket = new Dictionary<IPAddress, List<RawPacket>>();

            var dev = new CaptureFileReaderDevice(file);
            try
            {
                dev.Open();
                RawCapture packet;
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
                        toMstcp.Clear();
                        toAdapter.Clear();
                        //foreach (var item in toMstcp)
                        //{
                        //    var p = Packet.ParsePacket(LinkLayers.Ethernet, item.Data).Extract<IPv4Packet>();
                        //    var src = p.SourceAddress;
                        //    if (historyPacket.ContainsKey(src))
                        //        historyPacket[src].Add(item);
                        //    else
                        //    {
                        //        Console.WriteLine($"{src} => {p.DestinationAddress}");
                        //        historyPacket.Add(src, new List<RawPacket>());
                        //    }
                        //    //Console.WriteLine($"{p}");
                        //}
                    }


                }


            }
            finally
            {
                dev.Close();
            }
        }
    }
}
