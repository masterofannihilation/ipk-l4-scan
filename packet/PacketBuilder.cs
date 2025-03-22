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
        byte[] ipV4Header = new IpV4Header(srcIp, dstIp, (uint)protocol).CreateHeader();
        byte[] packet = [];
        
        if (protocol == Protocol.Tcp)
        {
            packet = CreateTcpPacket(ipV4Header, dstPort);
        }
        if (protocol == Protocol.Udp)
        {
            packet = CreateUdpPacket(ipV4Header, dstPort);
        }

        return packet;
    }
    private byte[] CreateIpV6Packet(ushort dstPort, Protocol protocol)
    {
        byte[] ipV6Header = new IpV6Header(srcIp,dstIp, (uint)protocol).CreateHeader();
        byte[] packet = [];
        
        if (protocol == Protocol.Tcp)
        {
            packet = CreateTcpPacket(ipV6Header, dstPort);
        }
        if (protocol == Protocol.Udp)
        {
            packet = CreateUdpPacket(ipV6Header, dstPort);
        }

        return packet;
    }
    private byte[] CreateTcpPacket(byte[] ipHeader, ushort dstPort)
    {
        byte[] tcpHeader = new TcpHeader(srcPort, dstPort, srcIp, dstIp).CreateHeader();
        byte[] packet = new byte[ipHeader.Length + tcpHeader.Length];
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(tcpHeader, 0, packet, ipHeader.Length, tcpHeader.Length);
        return packet;
    }

    private byte[] CreateUdpPacket(byte[] ipHeader, ushort dstPort)
    {
        byte[] udpHeader = new UdpHeader(srcPort, dstPort, srcIp, dstIp).CreateHeader();
        byte[] packet = new byte[ipHeader.Length + udpHeader.Length];
        Array.Copy(ipHeader, 0, packet, 0, ipHeader.Length);
        Array.Copy(udpHeader, 0, packet, ipHeader.Length, udpHeader.Length);
        
        return packet;
    }
}