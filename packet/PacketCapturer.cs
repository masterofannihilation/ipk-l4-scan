using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using SharpPcap;

namespace ipk_l4_scan.packet;

public class PacketCapturer
{
    public static void CapturePacket(string interfaceName, Socket scannerSocket)
    {
        var device = GetCaptureDevice(interfaceName);
        device.Open(DeviceModes.MaxResponsiveness);
        device.OnPacketArrival += PacketHandler;

        SetDeviceFilter(scannerSocket, device);

        device.StartCapture();

        Console.CancelKeyPress += (_, e) =>
        {
            device.StopCapture();
            device.Close();
        };

        while (true)
        {
            Thread.Sleep(100);
        }
    }

    private static void SetDeviceFilter(Socket scannerSocket, ICaptureDevice device)
    {
        if (scannerSocket.LocalEndPoint != null)
        {
            int scannerPort = ((IPEndPoint)scannerSocket.LocalEndPoint).Port;
            device.Filter = $"dst port {scannerPort} or icmp";
        }
        else
        {
            throw new Exception("LocalEndPoint is null. Socket may not be bound or connected.");
        }
    }

    private static ICaptureDevice GetCaptureDevice(string interfaceName)
    {
        var devices = CaptureDeviceList.Instance;
        return devices.FirstOrDefault(d => d.Name == interfaceName) ??
               throw new Exception($"Cannot find interface '{interfaceName}'.");
    }
    
     private static void PacketHandler(object sender, SharpPcap.PacketCapture e)
    {
        var rawPacket = e.GetPacket();
        var packetData = rawPacket.Data;

        ParseEthernetHeader(packetData);
    }

    private static void ParseEthernetHeader(byte[] packetData)
    {
        ushort ethernetType = (ushort)(packetData[12] << 8 | packetData[13]);

        if (ethernetType == 0x0800)
        {
            ParseIpv4Header(packetData);
        }
    }

    private static void ParseIpv4Header(byte[] packetData)
    {
        byte ipHeaderLength = (byte)((packetData[14] & 0x0F) * 4);
        byte protocol = packetData[23];

        if (protocol == 6)
        {
            ParseTcpHeader(packetData, ipHeaderLength);
        }

        if (protocol == 1)
        {
            ParseIcmpHeader(packetData, ipHeaderLength);
        }
    }

    private static void ParseTcpHeader(byte[] packetData, byte ipHeaderLength)
    {
        int tcpHeaderStart = 14 + ipHeaderLength;

        ushort sourcePort = (ushort)((packetData[tcpHeaderStart] << 8) | packetData[tcpHeaderStart + 1]);
        byte tcpFlags = packetData[tcpHeaderStart + 13];

        HandleTcpFlags(tcpFlags, sourcePort);
    }

    private static void HandleTcpFlags(byte flags, ushort sourcePort)
    {
        //SYN + ACK
        if (flags == 0x12)
        {
            Console.Write($"{sourcePort}\\tcp");
            Console.SetCursorPosition(15, Console.CursorTop);
            Console.Write("OPEN\n");
        }

        //RST
        if (flags == 0x04)
        {
            Console.Write($"{sourcePort}\\tcp");
            Console.SetCursorPosition(15, Console.CursorTop);
            Console.Write("CLOSED\n");
        }
    }

    private static void ParseIcmpHeader(byte[] packetData, byte ipHeaderLength)
    {
        int icmpHeaderStart = 14 + ipHeaderLength;
        byte icmpType = packetData[icmpHeaderStart];
        byte icmpCode = packetData[icmpHeaderStart + 1];

        // Only process ICMP Destination Unreachable (Type 3, Code 3)
        if (icmpType == 3 && icmpCode == 3)
        {
            // Extract the original (embedded) IP header inside the ICMP payload
            int embeddedIpHeaderStart = icmpHeaderStart + 8; // ICMP header is 8 bytes
            byte embeddedIpHeaderLength = (byte)((packetData[embeddedIpHeaderStart] & 0x0F) * 4);
            byte embeddedProtocol = packetData[embeddedIpHeaderStart + 9];

            if (embeddedProtocol == 17) // UDP (Protocol 17)
            {
                int embeddedUdpHeaderStart = embeddedIpHeaderStart + embeddedIpHeaderLength;
                ushort srcPort = (ushort)((packetData[embeddedUdpHeaderStart] << 8) | packetData[embeddedUdpHeaderStart + 1]);

                Console.Write($"{srcPort}\\udp");
                Console.SetCursorPosition(15, Console.CursorTop);
                Console.Write("CLOSED\n");
            }
        }
    }
}