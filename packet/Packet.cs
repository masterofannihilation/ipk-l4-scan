using System.Net;
using SharpPcap;
using System.Net.Sockets;
using PacketDotNet;
using ipk_l4_scan.headers;

namespace ipk_l4_scan.packet;

public class Packet
{
    private IPAddress srcIp;
    private IPAddress dstIp;
    private ushort srcPort;

    public Packet(IPAddress srcIp, IPAddress dstIp, int srcPort)
    {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = (ushort)srcPort;
    }
    public byte[] CraftPacket(ushort dstPort)
    {
        byte[] ipV4Header = new IpV4Header(srcIp, dstIp).ToByteArray();
        byte[] tcpHeader = new TcpHeader(srcPort, dstPort, srcIp, dstIp).ToByteArray();
        
        byte[] packet = new byte[ipV4Header.Length + tcpHeader.Length];
        Array.Copy(ipV4Header, 0, packet, 0, ipV4Header.Length);
        Array.Copy(tcpHeader, 0, packet, ipV4Header.Length, tcpHeader.Length);

        return packet;
    }

    public static void SendPacket(Socket socket, byte[] packet, IPEndPoint remoteEp)
    {
        try
        {
            socket.SendTo(packet, remoteEp);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            throw;
        }
    }

    public static void CapturePacket(string interfaceName)
    {
        var device = GetCaptureDevice(interfaceName);
        
        device.Open(DeviceModes.MaxResponsiveness);
        device.OnPacketArrival += PacketHandler;
        Console.WriteLine("Waiting for incoming packets... Press Ctrl+C to stop...");
        Console.WriteLine("");
        device.Filter = "src host 127.0.0.1";

        device.StartCapture(); // Použi neblokujúcu verziu

        Console.CancelKeyPress += (_, e) =>
        {
            device.StopCapture();
            device.Close();
        };

        while (true) { Thread.Sleep(100); }
    }

    private static ICaptureDevice GetCaptureDevice(string interfaceName)
    {
        var devices = CaptureDeviceList.Instance;
        return devices.FirstOrDefault(d => d.Name == interfaceName) ??
                throw new Exception($"Cannot find interface '{interfaceName}'.");
    }
    
    private static void PacketHandler(object sender, PacketCapture e)
    {
        var rawPacket = e.GetPacket();
        var timestamp = e.Header.Timeval.Date; // Get timestamp when the packet was received

        var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
        var tcpPacket = packet.Extract<TcpPacket>();

        if (tcpPacket != null)
        {
            var ipPacket = (IPPacket)tcpPacket.ParentPacket;
            IPAddress srcIp = ipPacket.SourceAddress;
            IPAddress dstIp = ipPacket.DestinationAddress;
            int srcPort = tcpPacket.SourcePort;
            int dstPort = tcpPacket.DestinationPort;
            uint sequenceNumber = tcpPacket.SequenceNumber;
            ushort flag = tcpPacket.Flags;

            // Console.WriteLine("[{0:HH:mm:ss.fff}] SRC IP:{1} SRC PORT:{2} DST IP:{3} DST PORT:{4} SEQ:{5} FLAG:{6}",
                // timestamp, srcIp, srcPort, dstIp, dstPort, sequenceNumber, flag);
            if (flag == 18)
            {
                Console.WriteLine($"PORT: {srcPort}     OPEN");
            }
        }
    }

}