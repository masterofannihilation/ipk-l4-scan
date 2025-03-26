using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.CommandLine.Parsing;
using System.Reflection.Metadata.Ecma335;

namespace ipk_l4_scan.packet
{
    public class PacketCapture
    {
        private readonly Socket _scannerSocket;
        private readonly Socket _scannerSocketV6;
        private readonly Socket _icmpSocket;
        private readonly Socket _icmpSocketV6;
        
        private SocketAsyncEventArgs _scannerEventArgs;
        private SocketAsyncEventArgs _scannerV6EventArgs;
        private SocketAsyncEventArgs _icmpEventArgs;
        private SocketAsyncEventArgs _icmpV6EventArgs;
        
        private readonly int _srcPort;
        private readonly ConcurrentDictionary<(int Port, int Protocol), byte> _ports;
        private readonly IPAddress _dstIp;

        public PacketCapture(Socket scannerSocket, int srcPort, ConcurrentDictionary<(int Port, int Protocol), byte> ports, IPAddress dstIp)
        {
            _scannerSocket = scannerSocket ?? throw new ArgumentNullException(nameof(scannerSocket));
            _scannerSocketV6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp); 
            _icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            _icmpSocketV6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            
            // Initialize SocketAsyncEventArgs for each socket
            _scannerEventArgs = new SocketAsyncEventArgs();
            _scannerV6EventArgs = new SocketAsyncEventArgs();
            _icmpEventArgs = new SocketAsyncEventArgs();
            _icmpV6EventArgs = new SocketAsyncEventArgs();

            // Set up event handlers
            _scannerEventArgs.Completed += OnReceiveCompleted;
            _scannerV6EventArgs.Completed += OnReceiveCompleted;
            _icmpEventArgs.Completed += OnReceiveCompleted;
            _icmpV6EventArgs.Completed += OnReceiveCompleted;

            // Assign buffers
            _scannerEventArgs.SetBuffer(new byte[65535], 0, 65535);
            _scannerV6EventArgs.SetBuffer(new byte[65535], 0, 65535);
            _icmpEventArgs.SetBuffer(new byte[65535], 0, 65535);
            _icmpV6EventArgs.SetBuffer(new byte[65535], 0, 65535);

            _dstIp = dstIp;
            _srcPort = srcPort;
            _ports = ports;
        }
    public Task CapturePacketAsync()
    {
        // Start receiving on all sockets
        StartReceiving(_scannerSocket, _scannerEventArgs);
        StartReceiving(_scannerSocketV6, _scannerV6EventArgs);
        StartReceiving(_icmpSocket, _icmpEventArgs);
        StartReceiving(_icmpSocketV6, _icmpV6EventArgs);
        return Task.CompletedTask;
    }

    private void StartReceiving(Socket socket, SocketAsyncEventArgs args)
    {
        if (!socket.ReceiveAsync(args))
        {
            // If the operation completes synchronously, call the handler directly
            OnReceiveCompleted(null, args);
        }
    }

    private void OnReceiveCompleted(object? sender, SocketAsyncEventArgs e)
    {
        if (e.BytesTransferred > 0 && e.SocketError == SocketError.Success)
        {
            // Process the received data
            byte[] buffer = new byte[e.BytesTransferred];
            if (e.Buffer != null) Array.Copy(e.Buffer, e.Offset, buffer, 0, e.BytesTransferred);

            // Analyze the packet
            AnalysePacket(buffer);

            // Continue receiving on the same socket
            Socket receivingSocket = e == _scannerEventArgs ? _scannerSocket :
                                    e == _scannerV6EventArgs ? _scannerSocketV6 :
                                    e == _icmpEventArgs ? _icmpSocket :
                                    _icmpSocketV6;

            if (!receivingSocket.ReceiveAsync(e))
            {
                OnReceiveCompleted(null, e);
            }
        }
    }

        
        private  void AnalysePacket(byte[] buffer)
        {
            // raw sockets will not receive whole IP datagram, but transport header directly
            //check if we got TCP header directly
            var dstPort = (ushort)((buffer[2] << 8) | buffer[3]);
            if (dstPort == _srcPort)
            {
                // create dummy packet just to pass something to HandleTransportLayer
                var dummyPacket = CreateDummyPacket((byte)6);
                HandleTransportLayer(buffer, dummyPacket);
            }
            
            //check if we got ICMPv6 header
            var type = buffer[0];
            var code = buffer[1];
            if (type == 1 && (code == 4 || code == 1))
            {
                var dummyPacket = CreateDummyPacket((byte)58);
                HandleTransportLayer(buffer, dummyPacket);
            }
            
            // else it's just an ipv4 packet
            var version = (byte)(buffer[0] >> 4);
            var parsedPacket = new IpPacket();
            if (version == 4)
            {
                parsedPacket = ParseIPv4Packet(buffer);
            }

            HandleTransportLayer(buffer, parsedPacket);
        }

        private IpPacket CreateDummyPacket(byte protocol)
        {
            if (_scannerSocket.LocalEndPoint is not IPEndPoint localEndPoint)
            {
                throw new InvalidOperationException("LocalEndPoint is null");
            }

            var dummyPacket = new IpPacket
            {
                SourceIp = localEndPoint.Address,
                Protocol = protocol
            };
            return dummyPacket;
        }

        private static IpPacket ParseIPv4Packet(byte[] buffer)
        {
            var ipv4Packet = new IpPacket
            {
                SourceIp = new IPAddress(new ReadOnlySpan<byte>(buffer, 12, 4)),
                Protocol = buffer[9],
            };
            return ipv4Packet;
        }

        private  void HandleTransportLayer(byte[] buffer, IpPacket? parsedPacket)
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
                        PrintInfo(_dstIp, parsedTcpHeader.SourcePort, parsedPacket.Protocol, parsedTcpHeader.Flags);
                    }
                    break;
                }
                // ICMP
                case { Protocol: 1 }:
                {
                    var parsedIcmpHeader = ParseIcmpHeader(buffer);
                    if (parsedIcmpHeader is { Type: 3, Code: 3 } && parsedIcmpHeader.SourcePort == _srcPort && parsedIcmpHeader.Protocol == 17) // ICMP port unreachable
                    {
                        // Mark the UDP port as closed
                        _ports.TryRemove((parsedIcmpHeader.DestinationPort, 17), out _);
                        PrintInfo(parsedPacket.SourceIp, (ushort)parsedIcmpHeader.DestinationPort, parsedIcmpHeader.Protocol, 0x04);
                    }

                    break;
                }
                // ICMPv6 (IPv6)
                case { Protocol: 58 }: // ICMPv6 protocol number
                {
                    var parsedIcmpV6Header = ParseIcmpV6Header(buffer);
                    if (parsedIcmpV6Header is { Type: 1, Code: 4 })
                    {
                        // Mark the UDP port as closed
                        _ports.TryRemove((parsedIcmpV6Header.DestinationPort, 17), out _);
                        PrintInfo(_dstIp, (ushort)parsedIcmpV6Header.DestinationPort, parsedIcmpV6Header.Protocol, 0x04);
                    }

                    break;
                }
            }
        }

        private TcpHeaderParser? ParseTcpHeader(byte[] buffer)
        {
            var tcpHeaderStart = CalcTcpHeaderStart(buffer);

            if (buffer.Length < tcpHeaderStart + 20) // Check if buffer contains a full TCP header
                return null;

            return new TcpHeaderParser
            {
                SourcePort = (ushort)((buffer[tcpHeaderStart] << 8) | buffer[tcpHeaderStart + 1]),
                DestinationPort = (ushort)((buffer[tcpHeaderStart + 2] << 8) | buffer[tcpHeaderStart + 3]),
                Flags = buffer[tcpHeaderStart + 13] // TCP flags are in the 13th byte of the TCP header
            };
        }

        private int CalcTcpHeaderStart(byte[] buffer)
        {
            int ipHeaderLength = (buffer[0] & 0x0F) * 4; // Calculate IP header length
            int tcpHeaderStart = ipHeaderLength; // TCP header starts after IP header
            
            // check if we get TCP header directly, in that case we need to set tcpHeaderStart to 0
            var dstPort = (ushort)((buffer[2] << 8) | buffer[3]);
            if (dstPort == _srcPort)
            {
                tcpHeaderStart = 0;
            }

            return tcpHeaderStart;
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

                icmpHeader.Protocol = buffer[originalPacketStart + 9];
                icmpHeader.DestinationPort = (buffer[transportHeaderStart + 2] << 8) | buffer[transportHeaderStart + 3];
                icmpHeader.SourcePort = (buffer[transportHeaderStart] << 8) | buffer[transportHeaderStart + 1];
            }
        }
        
        private IcmpHeaderParser? ParseIcmpV6Header(byte[] buffer)
        {
            // int ipV6HeaderLength = 40; // IPv6 header is fixed at 40 bytes
            // int icmpV6HeaderStart = ipV6HeaderLength; // ICMPv6 header starts after IPv6 header
            int icmpV6HeaderStart = 0;

            if (buffer.Length < icmpV6HeaderStart + 8) // Check if buffer contains a full ICMPv6 header
                return null;

            // Parse ICMPv6 header
            var icmpV6Header = new IcmpHeaderParser
            {
                Type = buffer[icmpV6HeaderStart], // ICMPv6 type (offset 0)
                Code = buffer[icmpV6HeaderStart + 1], // ICMPv6 code (offset 1)
            };

            ParseIcmpV6Type1(buffer, icmpV6Header, icmpV6HeaderStart);

            return icmpV6Header;
        }

        private static void ParseIcmpV6Type1(byte[] buffer, IcmpHeaderParser icmpv6Header, int icmpv6HeaderStart)
        {
            // If the ICMPv6 message is a Destination Unreachable (type 1), parse the original packet
            if (icmpv6Header.Type == 1)
            {
                int originalPacketStart = icmpv6HeaderStart + 8; // Original packet starts after ICMPv6 header
                int originalIpHeaderLength = 40; // IPv6 header is fixed at 40 bytes
                int transportHeaderStart = originalPacketStart + originalIpHeaderLength;

                // Extract the protocol from the original IPv6 packet
                icmpv6Header.Protocol = buffer[originalPacketStart + 6]; // Next header field in IPv6 header
                icmpv6Header.DestinationPort = (buffer[transportHeaderStart + 2] << 8) | buffer[transportHeaderStart + 3];
                icmpv6Header.SourcePort = (buffer[transportHeaderStart] << 8) | buffer[transportHeaderStart + 1];
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
    public IPAddress SourceIp { get; set; } = IPAddress.None;
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
    public int DestinationPort { get; set; } // Destination port in the original packet
    public int SourcePort { get; set; } // Source port in the original packet
    public byte Protocol { get; set; } // Protocol number
}