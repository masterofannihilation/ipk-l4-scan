using System.Net;
using System.Net.Sockets;
using ipk_l4_scan.headers;

namespace ipk_l4_scan.packet;

public class PacketBuilder(IPAddress srcIp, IPAddress dstIp, int srcPort)
{
    private IPAddress srcIp = srcIp;
    private IPAddress dstIp = dstIp;
    private ushort srcPort = (ushort)srcPort;

    public enum Protocol
    {
        Tcp = 6,
        Udp = 17
    }

    public byte[] CreatePacket(ushort dstPort, Protocol protocol)
    {
        byte[] packet = [];
        if (dstIp.AddressFamily == AddressFamily.InterNetwork)
        {
            packet = CreateIpV4Packet(dstPort, protocol);
        }

        if (dstIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            packet = CreateIpV6Packet(dstPort, protocol);
        }

        return packet;
    }

    private byte[] CreateIpV4Packet(ushort dstPort, Protocol protocol)
    {
        IHeader ipV4Header = new IpV4Header(srcIp, dstIp, (uint)protocol);
        byte[] ipV4HeaderBytes = ipV4Header.CreateHeader();
        byte[] packet = [];
        
        if (protocol == Protocol.Tcp)
        {
            packet = CreateTcpPacket(ipV4HeaderBytes, dstPort);
        }
        if (protocol == Protocol.Udp)
        {
            packet = CreateUdpPacket(ipV4HeaderBytes, dstPort);
        }

        return packet;
    }
    private byte[] CreateIpV6Packet(ushort dstPort, Protocol protocol)
    {
        IHeader ipV6Header = new IpV6Header(srcIp,dstIp, (uint)protocol);
        byte[] ipV6HeaderBytes = ipV6Header.CreateHeader();
        byte[] packet = [];
        
        if (protocol == Protocol.Tcp)
        {
            packet = CreateTcpPacket(ipV6HeaderBytes, dstPort);
        }
        if (protocol == Protocol.Udp)
        {
            packet = CreateUdpPacket(ipV6HeaderBytes, dstPort);
        }

        return packet;
    }
    private byte[] CreateTcpPacket(byte[] ipHeader, ushort dstPort)
    {
        IHeader tcpHeader = new TcpHeader(srcPort, dstPort, srcIp, dstIp);
        byte[] tcpHeaderBytes = tcpHeader.CreateHeader();
        
        byte[] packet = new byte[ipHeader.Length + tcpHeaderBytes.Length];
        // put ip header and tcp header together tcp header at the end of ip header
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeaderBytes, 0, packet, ipHeader.Length, tcpHeaderBytes.Length);
        return packet;
    }

    private byte[] CreateUdpPacket(byte[] ipHeader, ushort dstPort)
    {
        // Change payload lenght in ip header
        ipHeader[4] = 8 >> 8;
        ipHeader[5] = 8 & 0xFF;
        
        IHeader udpHeader = new UdpHeader(srcPort, dstPort, srcIp, dstIp);
        byte[] udpHeaderBytes = udpHeader.CreateHeader();
        byte[] packet = new byte[ipHeader.Length + udpHeaderBytes.Length];
        // put ip header and tcp header together udp header at the end of ip header
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(udpHeaderBytes, 0, packet, ipHeader.Length, udpHeaderBytes.Length);
        
        return packet;
    }
}