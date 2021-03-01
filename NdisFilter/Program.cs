/*************************************************************************/
/*              Copyright (c) 2000-2018 NT Kernel Resources.             */
/*                           All Rights Reserved.                        */
/*                          http://www.ntkernel.com                      */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  Program.cs                                              */
/*                                                                       */
/* Abstract: Defines the entry point for the console application.        */
/*                                                                       */
/* Environment:                                                          */
/*   .NET User mode                                                      */
/*                                                                       */
/*************************************************************************/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

using NdisApi;

using NdisFilter.Core;

using NLog;

using ProtocolType = PacketDotNet.ProtocolType;

namespace NdisFilter
{

    class Program
    {
        private static ILogger logger = LogManager.GetCurrentClassLogger();
        // used to stop the capture loop
        private static Boolean stopCapturing = false;
        private static ManualResetEvent packetEvent = new ManualResetEvent(false);

        // Useed for sending NDIS request to the network interface
        private const UInt32 OID_802_3_CURRENT_ADDRESS = 0x01010102;
        private const UInt32 OID_GEN_MAXIMUM_TOTAL_SIZE = 0x00010111;
        private const UInt32 OID_GEN_PHYSICAL_MEDIUM = 0x00010202;

        private static NdisApiDotNet ndisapi = new NdisApiDotNet(null);

        static void Main(string[] args)
        {
            if (!ndisapi.IsDriverLoaded())
            {
                Console.WriteLine("WinpkFilter driver is not loaded. Exiting.");
                return;
            }

            UInt32 driverVersion = ndisapi.GetVersion();
            UInt32 majorVersion = (driverVersion & (0xF000)) >> 12;
            UInt32 minorVersion1 = (driverVersion & (0xFF000000)) >> 24;
            UInt32 minorVersion2 = (driverVersion & (0xFF0000)) >> 16;

            if (ndisapi != null)
                Console.WriteLine($"Detected Windows Packet Filter version {majorVersion}.{minorVersion1}.{minorVersion2}");

            Console.WriteLine();

            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();

            if (!adapterList.Item1)
            {
                Console.WriteLine("WinpkFilter failed to query active interfaces. Exiting.");
                return;
            }

            if (adapterList.Item2.Count > 0)
                Console.WriteLine("Available network interfaces: ");

            Console.WriteLine();

            int counter = 0;
            foreach (var adapter in adapterList.Item2)
            {
                Console.WriteLine($"{++counter}) {adapter.FriendlyName}");
                Console.WriteLine($"\t Internal name: {adapter.Name}");
                Console.WriteLine($"\t Handle: {adapter.Handle.ToString("x")}");
                Console.WriteLine($"\t MAC: {adapter.CurrentAddress}");
                Console.WriteLine($"\t Medium: {adapter.Medium}");
                Console.WriteLine($"\t MTU: {adapter.Mtu}");

                if (adapter.Medium == NDIS_MEDIUM.NdisMediumWan)
                {
                    var rasLinkInfoList = ndisapi.GetRasLinks(adapter.Handle);

                    if (rasLinkInfoList.Item1 && (rasLinkInfoList.Item2.Count > 0))
                    {
                        foreach (var e in rasLinkInfoList.Item2)
                        {
                            Console.WriteLine($"----------------------------------------------------------------");
                            Console.WriteLine($"\t\tLinkSpeed = {e.LinkSpeed}");
                            Console.WriteLine($"\t\tMTU: {e.MaximumTotalSize}");
                            Console.WriteLine($"\t\tLocalAddress: {e.LocalAddress}");
                            Console.WriteLine($"\t\tRemoteAddress: {e.RemoteAddress}");

                            Byte[] ipAddress = new Byte[4];
                            Array.Copy(e.ProtocolBuffer, 584, ipAddress, 0, 4);
                            IPAddress ipV4 = new IPAddress(ipAddress);
                            Array.Copy(e.ProtocolBuffer, 588, ipAddress, 0, 4);
                            IPAddress ipMaskV4 = new IPAddress(ipAddress);

                            Console.WriteLine($"\t\tIPv4: {ipV4} Mask: {ipMaskV4}");
                            Console.WriteLine($"----------------------------------------------------------------");
                        }
                    }
                }

                Console.WriteLine();
            }

            Console.Write("Select network interface: ");
            int index = Convert.ToInt32(Console.ReadLine());

            if (index > adapterList.Item2.Count)
            {
                Console.WriteLine($"Wrong interface index {index}");
                return;
            }

            #region Testing NdisrdRequest API call
            Console.WriteLine();
            Console.WriteLine($"Probing NDIS requests on: {adapterList.Item2[index - 1].FriendlyName}:");
            Console.WriteLine();

            PacketOidData oidRequest = new PacketOidData();
            oidRequest.Adapter = adapterList.Item2[index - 1].Handle;
            oidRequest.Oid = OID_802_3_CURRENT_ADDRESS;
            oidRequest.Data = new byte[6];

            if (ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_802_3_CURRENT_ADDRESS:     Status = OK     Value: {new PhysicalAddress(oidRequest.Data)}");
            else
                Console.WriteLine($@"OID_802_3_CURRENT_ADDRESS:     Status = FAILED");

            oidRequest.Oid = OID_GEN_MAXIMUM_TOTAL_SIZE;
            oidRequest.Data = new byte[4];

            if (ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_GEN_MAXIMUM_TOTAL_SIZE:    Status = OK     Value: {BitConverter.ToUInt32(oidRequest.Data, 0)}");
            else
                Console.WriteLine($@"OID_GEN_MAXIMUM_TOTAL_SIZE:    Status = FAILED");

            oidRequest.Oid = OID_GEN_PHYSICAL_MEDIUM;

            if (ndisapi.NdisrdRequest(oidRequest, false))
                Console.WriteLine($@"OID_GEN_PHYSICAL_MEDIUM:       Status = OK     Value: {(NdisPhysicalMedium)BitConverter.ToUInt32(oidRequest.Data, 0)}");
            else
                Console.WriteLine($@"OID_GEN_PHYSICAL_MEDIUM:       Status = FAILED");
            #endregion

            #region Testing static filters
            Console.WriteLine();

            LoadBf4GameFilter(adapterList.Item2[index - 1].Handle);
            #endregion

            // Register a cancel handler that lets us break out of our capture loop
            Console.CancelKeyPress += HandleCancelKeyPress;

            ndisapi.SetAdapterMode(
                adapterList.Item2[index - 1].Handle,
                MSTCP_FLAGS.MSTCP_FLAG_RECV_TUNNEL | MSTCP_FLAGS.MSTCP_FLAG_SENT_TUNNEL
                );

            ndisapi.SetPacketEvent(adapterList.Item2[index - 1].Handle, packetEvent);

            Console.WriteLine($"-- Filtering on {adapterList.Item2[index - 1].FriendlyName}, hit 'ctrl-c' to stop...");

            // Unmanaged memory resource for sending receiving bulk of packets
            // Maximum number of packets to send/receive = 64
            NdisBufferResource buffer = new NdisBufferResource(Settings.Default.Buffer);

            // Lists for re-injecting packets
            List<RawPacket> toAdapter = new List<RawPacket>(Settings.Default.Buffer);
            List<RawPacket> toMstcp = new List<RawPacket>(Settings.Default.Buffer);
            INetFilter filter = new NetFilter(Settings.Default.Allows, logger);
            Stopwatch stopwatch = Stopwatch.StartNew();

            do
            {
                packetEvent.WaitOne();

                // Delay clear IP address list when no player in server
                if (stopwatch.ElapsedMilliseconds > 5 * 1000)
                {
                    logger.Info($"{DateTime.Now} allow list clear");
                    filter.Init();
                }
                stopwatch.Restart();

                #region Bulk of packets read/write

                var packetList = ndisapi.ReadPackets(adapterList.Item2[index - 1].Handle, buffer);
                while (packetList.Item1)
                {
                    filter.Run(packetList.Item2, toMstcp, toAdapter);

                    if (toMstcp.Count > 0)
                    {
                        // If we have packets to forward upwards the network stack then do it here
                        ndisapi.SendPacketsToMstcp(adapterList.Item2[index - 1].Handle, buffer, toMstcp);
                        toMstcp.Clear();
                    }

                    if (toAdapter.Count > 0)
                    {
                        // If we have packets to forward downwards the network stack then do it here
                        ndisapi.SendPacketsToAdapter(adapterList.Item2[index - 1].Handle, buffer, toAdapter);
                        toAdapter.Clear();
                    }

                    packetList = ndisapi.ReadPackets(adapterList.Item2[index - 1].Handle, buffer);
                };

                #endregion
                packetEvent.Reset();

            } while (!stopCapturing);

            Console.WriteLine("-- Filtering stopped");

            //
            // Release driver and associated resources
            //
            buffer.Dispose();

            ndisapi.SetPacketEvent(adapterList.Item2[index - 1].Handle, null);

            ndisapi.SetAdapterMode(
                adapterList.Item2[index - 1].Handle,
                0
                );

            //
            // Display loaded static filters
            //
            DumpStaticFilters();
        }

        private static bool LoadBf4GameFilter(IntPtr adapterHandle)
        {
            var filterList = new List<StaticFilter>(3);

            //
            // Initialize static filters
            //
            Console.WriteLine($"Port:{Settings.Default.Port}");
            ushort port = Settings.Default.Port;

            // 1.Incoming UDP filter: REDIRECT IN UDP packets with dest PORT
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Udp
                ),


                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                    new TcpUdpFilter.PortRange(),
                    new TcpUdpFilter.PortRange { startRange = port, endRange = port },
                    0)
                ));

            // 2.Outcoming UDP filter: REDIRECT IN UDP packets with src PORT
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                null,
                new IpAddressFilter(
                    AddressFamily.InterNetwork,
                    IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_PROTOCOL,
                    null,
                    null,
                    (byte)ProtocolType.Udp
                ),


                new TcpUdpFilter(
                    TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_SRC_PORT,
                    new TcpUdpFilter.PortRange { startRange = port, endRange = port },
                    new TcpUdpFilter.PortRange(),
                    0)
                ));

            // 3.Pass over everything else
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND | PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_PASS,
                0,
                null,
                null,
                null
                ));

            // Load static filter into the driver
            return ndisapi.SetPacketFilterTable(filterList);
        }
        static void HandleCancelKeyPress(Object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("-- Stopping packet filter");
            stopCapturing = true;
            packetEvent.Set();

            e.Cancel = true;
        }

        private static void DumpStaticFilters()
        {
            // Query current filters and print the stats
            var currentFilters = ndisapi.GetPacketFilterTable();

            if (currentFilters.Item1)
            {
                if (currentFilters.Item2.Count > 0)
                {
                    Console.WriteLine($"{currentFilters.Item2.Count} static filters were loaded into the driver:");
                    Console.WriteLine();

                    foreach (var filter in currentFilters.Item2)
                    {
                        Console.WriteLine($"{filter.ToString()}");
                        Console.WriteLine();
                    }
                }
                else
                {
                    Console.WriteLine("No static filters were loaded into the driver");
                }
            }
            else
            {
                Console.WriteLine("Failed to query filters stats from the driver");
            }
        }
    }

    // Physical Medium Type definitions. Used with OID_GEN_PHYSICAL_MEDIUM.
    //
    enum NdisPhysicalMedium
    {
        NdisPhysicalMediumUnspecified,
        NdisPhysicalMediumWirelessLan,
        NdisPhysicalMediumCableModem,
        NdisPhysicalMediumPhoneLine,
        NdisPhysicalMediumPowerLine,
        NdisPhysicalMediumDSL,      // includes ADSL and UADSL (G.Lite)
        NdisPhysicalMediumFibreChannel,
        NdisPhysicalMedium1394,
        NdisPhysicalMediumWirelessWan,
        NdisPhysicalMediumNative802_11,
        NdisPhysicalMediumBluetooth,
        NdisPhysicalMediumInfiniband,
        NdisPhysicalMediumWiMax,
        NdisPhysicalMediumUWB,
        NdisPhysicalMedium802_3,
        NdisPhysicalMedium802_5,
        NdisPhysicalMediumIrda,
        NdisPhysicalMediumWiredWAN,
        NdisPhysicalMediumWiredCoWan,
        NdisPhysicalMediumOther,
        NdisPhysicalMediumMax       // Not a real physical type, defined as an upper-bound
    };
}
