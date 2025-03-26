using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace ipk_l4_scan.headers;

public class UdpHeader(ushort srcPort, ushort dstPort, IPAddress srcIp, IPAddress dstIp) : IHeader
{
    private readonly ushort _length = 8; // UDP header length
    private ushort _checksum;

    public byte[] CreateHeader()
    {
        byte[] header = new byte[8];

        // Set source and destination ports
        header[0] = (byte)(srcPort >> 8);
        header[1] = (byte)(srcPort & 0xFF);
        header[2] = (byte)(dstPort >> 8);
        header[3] = (byte)(dstPort & 0xFF);

        // Set UDP length
        header[4] = (byte)(_length >> 8);
        header[5] = (byte)(_length & 0xFF);

        // Calculate checksum based on IP version
        if (srcIp.AddressFamily == AddressFamily.InterNetworkV6)
            _checksum = PrepareIPv6PseudoHeader(header);
        else
            _checksum = PrepareIPv4PseudoHeader(header);

        // Set checksum in header
        header[6] = (byte)(_checksum >> 8);
        header[7] = (byte)(_checksum & 0xFF);

        return header;
    }

    private ushort PrepareIPv4PseudoHeader(byte[] udpHeader)
    {
        var pseudoHeader = new byte[12 + udpHeader.Length];

        // Copy source and destination IP addresses (4 bytes each)
        Array.Copy(srcIp.GetAddressBytes(), 0, pseudoHeader, 0, 4);
        Array.Copy(dstIp.GetAddressBytes(), 0, pseudoHeader, 4, 4);

        // Protocol (UDP = 17)
        pseudoHeader[8] = 0;
        pseudoHeader[9] = 17;

        // UDP length
        pseudoHeader[10] = (byte)(_length >> 8);
        pseudoHeader[11] = (byte)(_length & 0xFF);

        // Copy UDP header
        Array.Copy(udpHeader, 0, pseudoHeader, 12, udpHeader.Length);

        return CalculateChecksum(pseudoHeader);
    }

    private ushort PrepareIPv6PseudoHeader(byte[] udpHeader)
    {
        var pseudoHeader = new byte[40 + udpHeader.Length];

        // Copy source and destination IP addresses (16 bytes each)
        Array.Copy(srcIp.GetAddressBytes(), 0, pseudoHeader, 0, 16);
        Array.Copy(dstIp.GetAddressBytes(), 0, pseudoHeader, 16, 16);

        // Payload length (UDP header length)
        pseudoHeader[32] = (byte)(_length >> 8);
        pseudoHeader[33] = (byte)(_length & 0xFF);

        // Next header (UDP = 17)
        pseudoHeader[34] = 0;
        pseudoHeader[35] = 17;

        // Reserved (3 bytes, set to 0)
        pseudoHeader[36] = 0;
        pseudoHeader[37] = 0;
        pseudoHeader[38] = 0;
        pseudoHeader[39] = 0;

        // Copy UDP header
        Array.Copy(udpHeader, 0, pseudoHeader, 40, udpHeader.Length);

        return CalculateChecksum(pseudoHeader);
    }

    private ushort CalculateChecksum(byte[] buffer)
    {
        uint sum = 0;

        // Process each 16-bit word (2 bytes at a time)
        for (int i = 0; i < buffer.Length; i += 2)
        {
            ushort word = (ushort)((buffer[i] << 8) | (i + 1 < buffer.Length ? buffer[i + 1] : 0));
            sum += word;

            // Handle carry bit if necessary
            if (sum > 0xFFFF)
            {
                sum = (sum & 0xFFFF) + 1;
            }
        }

        // One's complement
        return (ushort)~sum;
    }
}