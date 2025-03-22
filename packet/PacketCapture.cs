using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ipk_l4_scan.packet;

public class PacketCapture
{
    private readonly Socket _scannerSocket;
    private readonly int _scannerPort;
    private readonly ConcurrentDictionary<int, bool> _tcpResponseTracker;
    private readonly ConcurrentDictionary<int, bool> _udpResponseTracker;
    private readonly CancellationTokenSource _cts;

    public PacketCapture(Socket scannerSocket, int srcPort, ConcurrentDictionary<int, bool> tcpResponseTracker, ConcurrentDictionary<int, bool> udpResponseTracker, CancellationTokenSource cts)
    {
        _scannerSocket = scannerSocket ?? throw new ArgumentNullException(nameof(scannerSocket));
        _scannerPort = srcPort;
        _tcpResponseTracker = tcpResponseTracker ?? throw new ArgumentNullException(nameof(tcpResponseTracker));
        _udpResponseTracker = udpResponseTracker ?? throw new ArgumentNullException(nameof(udpResponseTracker));
        _cts = cts;
    }

    public async Task CapturePacket()
    {
        try
        {
            byte[] buffer = new byte[65535];
            while (!_cts.Token.IsCancellationRequested)
            {
                var result = await _scannerSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None, _cts.Token);

                if (result <= 0) continue;

                byte version = (byte)(buffer[0] >> 4);
                AnalysePacket(version, buffer);
            }
        }
        catch (Exception ex)
        {
        }
    }

    private void AnalysePacket(byte version, byte[] buffer)
    {
        var parsedPacket = new IpPacket();
        if (version == 4)
        {
            parsedPacket = ParseIPv4Packet(buffer);
        }
        
        HandleTransportLayer(buffer, parsedPacket);
    }
    
    private void HandleTransportLayer(byte[] buffer, IpPacket? parsedPacket)
    {
        if (parsedPacket is { Protocol: 6 }) // TCP
        {
            var parsedTcpHeader = ParseTcpHeader(buffer);
            if (parsedTcpHeader != null && parsedTcpHeader.DestinationPort == _scannerPort)
            {
                // Mark TCP port as responded
                _tcpResponseTracker[parsedTcpHeader.SourcePort] = true;
                PrintInfo(parsedPacket.SourceIP, parsedTcpHeader.SourcePort, parsedPacket.Protocol, parsedTcpHeader.Flags);
            }
        }
        else if (parsedPacket is { Protocol: 1 }) // ICMP
        {
            var parsedIcmpHeader = ParseIcmpHeader(buffer);
            if (parsedIcmpHeader is { Type: 3, Code: 3 }) // ICMP port unreachable
            {
                // Mark the UDP port as closed
                _udpResponseTracker[parsedIcmpHeader.DestinationPort] = true;
                Console.WriteLine($"{parsedPacket.SourceIP} {parsedIcmpHeader.DestinationPort} udp closed");
            }
        }
    }

    private IpPacket? ParseIPv4Packet(byte[] buffer)
    {
        IpPacket ipv4Packet = new IpPacket
        {
            SourceIP = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4)),
            DestinationIP = new IPAddress(new ReadOnlySpan<byte>(buffer, 16, 4)),
            Protocol = buffer[9],
        };
        return ipv4Packet;
    }
    
    private TcpHeaderParser? ParseTcpHeader(byte[] buffer)
    {
        int ipHeaderLength = (buffer[0] & 0x0F) * 4; // Calculate IP header length
        int tcpHeaderStart = ipHeaderLength; // TCP header starts after IP header

        if (buffer.Length < tcpHeaderStart + 20) // Check if buffer contains a full TCP header
            return null;

        return new TcpHeaderParser
        {
            SourcePort = (ushort)((buffer[tcpHeaderStart] << 8) | buffer[tcpHeaderStart + 1]),
            DestinationPort = (ushort)((buffer[tcpHeaderStart + 2] << 8) | buffer[tcpHeaderStart + 3]),
            Flags = buffer[tcpHeaderStart + 13] // TCP flags are in the 13th byte of the TCP header
        };
    }
    
    private IcmpHeaderParser? ParseIcmpHeader(byte[] buffer)
    {
        int ipHeaderLength = (buffer[0] & 0x0F) * 4; // Calculate IP header length
        int icmpHeaderStart = ipHeaderLength; // ICMP header starts after IP header

        if (buffer.Length < icmpHeaderStart + 8) // Check if buffer contains a full ICMP header
            return null;

        // Parse ICMP header
        var icmpHeader = new IcmpHeaderParser
        {
            Type = buffer[icmpHeaderStart], // ICMP type (offset 0)
            Code = buffer[icmpHeaderStart + 1], // ICMP code (offset 1)
        };

        ParseIcmpType3(buffer, icmpHeader, icmpHeaderStart);

        return icmpHeader;
    }

    private static void ParseIcmpType3(byte[] buffer, IcmpHeaderParser icmpHeader, int icmpHeaderStart)
    {
        // If the ICMP message is a Destination Unreachable (type 3), parse the original packet
        if (icmpHeader.Type == 3)
        {
            int originalPacketStart = icmpHeaderStart + 8; // Original packet starts after ICMP header
            int originalIpHeaderLength = (buffer[originalPacketStart] & 0x0F) * 4; // IPv4 header length
            int transportHeaderStart = originalPacketStart + originalIpHeaderLength;

            // Check if the original packet is UDP (protocol 17)
            byte protocol = buffer[originalPacketStart + 9]; // Protocol field in IPv4 header
            if (protocol == 17) // UDP
            {
                // Parse destination port in the original UDP packet
                icmpHeader.DestinationPort = (buffer[transportHeaderStart + 2] << 8) | buffer[transportHeaderStart + 3];
            }
        }
    }

    private static void PrintInfo(IPAddress ipAddress, ushort sourcePort, byte protocol, byte flags)
    {
        string protocolName = protocol switch
        {
            6 => "tcp",
            17 => "udp",
            _ => "unknown"
        };
        string flagName = flags switch
        {
            0x04 => "closed",
            0x12 => "open",
            _ => "unknown"
        };
        Console.WriteLine($"{ipAddress} {sourcePort} {protocolName} {flagName}");
    }
}

public class IpPacket
{
    public IPAddress SourceIP { get; set; }
    public IPAddress DestinationIP { get; set; }
    public byte Protocol { get; set; }
}

public class TcpHeaderParser
{
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }
    public byte Flags { get; set; } // TCP flags
}

public class IcmpHeaderParser
{
    public byte Type { get; set; } // ICMP message type
    public byte Code { get; set; } // ICMP message code
    public ushort SequenceNumber { get; set; } // Sequence number
    public int DestinationPort { get; set; } // Destination port in the original packet
    public int SourcePort { get; set; } // Source port in the original packet
}