using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;

namespace ipk_l4_scan.packet
{
    public class PacketCapture
    {
        private readonly Socket _scannerSocket;
        private readonly Socket _icmpSocket; // ICMP socket
        private readonly int _srcPort;
        private readonly ConcurrentDictionary<(int Port, int Protocol), byte> _ports;

        public PacketCapture(Socket scannerSocket, int srcPort, ConcurrentDictionary<(int Port, int Protocol), byte> ports)
        {
            _scannerSocket = scannerSocket ?? throw new ArgumentNullException(nameof(scannerSocket));
            _srcPort = srcPort;
            _ports = ports;

            // Create ICMP socket
            _icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        }

        public async Task CapturePacketAsync(CancellationToken token)
        {
            byte[] buffer = new byte[65535];

            // Start receiving from both the scanner socket and ICMP socket
            var scannerTask = ReceiveFromScannerSocketAsync(buffer, token);
            var icmpTask = ReceiveFromIcmpSocketAsync(buffer, token);

            await Task.WhenAll(scannerTask, icmpTask);
        }

        private async Task ReceiveFromScannerSocketAsync(byte[] buffer, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                var result = await _scannerSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

                if (result <= 0) continue;

                byte version = (byte)(buffer[0] >> 4);
                AnalysePacket(version, buffer);
            }
        }

        private async Task ReceiveFromIcmpSocketAsync(byte[] buffer, CancellationToken token)
        {
            // Bind ICMP socket to any IP address
            _icmpSocket.Bind(new IPEndPoint(IPAddress.Any, 0));

            while (!token.IsCancellationRequested)
            {
                var result = await _icmpSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);

                if (result <= 0) continue;

                byte version = (byte)(buffer[0] >> 4);
                AnalysePacket(version, buffer);
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
            switch (parsedPacket)
            {
                // TCP
                case { Protocol: 6 }:
                {
                    var parsedTcpHeader = ParseTcpHeader(buffer);
                    if (parsedTcpHeader != null && parsedTcpHeader.DestinationPort == _srcPort)
                    {
                        _ports.TryRemove((parsedTcpHeader.SourcePort, 6), out _);
                        PrintInfo(parsedPacket.SourceIP, parsedTcpHeader.SourcePort, parsedPacket.Protocol, parsedTcpHeader.Flags);
                    }

                    break;
                }
                // ICMP
                case { Protocol: 1 }:
                {
                    var parsedIcmpHeader = ParseIcmpHeader(buffer);
                    if (parsedIcmpHeader is { Type: 3, Code: 3 }) // ICMP port unreachable
                    {
                        // Mark the UDP port as closed
                        _ports.TryRemove((parsedIcmpHeader.DestinationPort, 17), out _);
                        PrintInfo(parsedPacket.SourceIP, (ushort)parsedIcmpHeader.DestinationPort, parsedPacket.Protocol, 0x04);
                    }

                    break;
                }
            }
        }

        private IpPacket ParseIPv4Packet(byte[] buffer)
        {
            var ipv4Packet = new IpPacket
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
                    icmpHeader.SourcePort = (buffer[transportHeaderStart] << 8) | buffer[transportHeaderStart + 1];
                }
            }
        }

        public void PrintInfo(IPAddress ipAddress, ushort sourcePort, byte protocol, byte flags)
        {
            string protocolName = protocol switch
            {
                6 => "tcp",
                17 => "udp",
                1 => "udp",
                _ => "unknown"
            };
            string flagName = flags switch
            {
                0x04 => "closed",
                0x14 => "closed",
                0x12 => "open",
                0 => "filtered",
                _ => "unknown"
            };
            Console.WriteLine($"{ipAddress} {sourcePort} {protocolName} {flagName}");
        }
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