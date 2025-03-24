using System.Net;
using System.Net.Sockets;

namespace ipk_l4_scan.headers;

public class TcpHeader(ushort srcPort, ushort destPort, IPAddress srcIp, IPAddress dstIp)
{
    private readonly uint _sequenceNumber = 0;
    private readonly uint _acknowledgmentNumber = 0;
    private readonly byte _dataOffset = 5;
    private readonly byte _reserved  = 0;
    private readonly byte _flags = 0b00000010; // SYN flag set
    private readonly ushort _windowSize = 1024;
    private ushort _checksum;
    private readonly ushort _urgentPointer = 0;
    
    public byte[] CreateHeader()
    {
        byte[] header = new byte[20];
        
        header[0] = (byte)(srcPort >> 8);
        header[1] = (byte)(srcPort & 0xFF);
        header[2] = (byte)(destPort >> 8);
        header[3] = (byte)(destPort & 0xFF);
        BitConverter.GetBytes(_sequenceNumber).CopyTo(header, 4);
        BitConverter.GetBytes(_acknowledgmentNumber).CopyTo(header, 8);
        header[12] = (byte)((_dataOffset << 4) | _reserved);
        header[13] = _flags;
        header[14] = (byte)(_windowSize >> 8);
        header[15] = (byte)(_windowSize & 0xFF);
        header[16] = 0; // Checksum before calc
        header[17] = 0;
        header[18] = (byte)(_urgentPointer >> 8);
        header[19] = (byte)(_urgentPointer & 0xFF);
        
        // calculate checksum based on IP version
        if (srcIp.AddressFamily == AddressFamily.InterNetworkV6)
            _checksum = PrepareIPv6PseudoHeader(header);
        else
            _checksum = PrepareIPv4PseudoHeader(header);
        header[16] = (byte)(_checksum >> 8);
        header[17] = (byte)(_checksum & 0xFF);
        
        
        
        return header;
    }

    private ushort PrepareIPv4PseudoHeader(byte[] header)
    {
        var pseudoHeader = new byte[12 + header.Length];

        if (srcIp.AddressFamily == AddressFamily.InterNetwork)
        {
            Array.Copy(srcIp.GetAddressBytes(), 0, pseudoHeader, 0, 4);
            Array.Copy(dstIp.GetAddressBytes(), 0, pseudoHeader, 4, 4);
        }
        else if (srcIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Array.Copy(srcIp.GetAddressBytes(), 0, pseudoHeader, 0, 16);
            Array.Copy(dstIp.GetAddressBytes(), 0, pseudoHeader, 16, 16);
        }

        pseudoHeader[8] = 0;
        pseudoHeader[9] = 6;
        pseudoHeader[10] = (byte)(header.Length >> 8);  // High byte of TCP length
        pseudoHeader[11] = (byte)(header.Length & 0xFF);  // Low byte of TCP length

        // Copy TCP header
        Array.Copy(header, 0, pseudoHeader, 12, header.Length);

        return CalculateCheckSum(pseudoHeader);
    }

    private ushort PrepareIPv6PseudoHeader(byte[] header)
    {
        // IPv6 pseudo-header is 40 bytes
        var pseudoHeader = new byte[40];

        // Copy source and destination addresses (16 bytes each)
        Array.Copy(srcIp.GetAddressBytes(), 0, pseudoHeader, 0, 16);
        Array.Copy(dstIp.GetAddressBytes(), 0, pseudoHeader, 16, 16);

        // Payload length (TCP header length)
        ushort payloadLength = (ushort)header.Length;
        pseudoHeader[32] = (byte)(payloadLength >> 8);
        pseudoHeader[33] = (byte)(payloadLength & 0xFF);

        // Next header (TCP = 6)
        pseudoHeader[34] = 0;
        pseudoHeader[35] = 6;

        // Reserved (3 bytes, set to 0)
        pseudoHeader[36] = 0;
        pseudoHeader[37] = 0;
        pseudoHeader[38] = 0;
        pseudoHeader[39] = 0;

        // Combine pseudo-header and TCP header
        var checksumBuffer = new byte[pseudoHeader.Length + header.Length];
        Array.Copy(pseudoHeader, 0, checksumBuffer, 0, pseudoHeader.Length);
        Array.Copy(header, 0, checksumBuffer, pseudoHeader.Length, header.Length);

        return CalculateCheckSum(checksumBuffer);
    }
    private ushort CalculateCheckSum(byte[] buffer)
    {
        uint checksum = 0;

        // Process each 16-bit word (2 bytes at a time)
        for (var i = 0; i < buffer.Length; i += 2)
        {
            ushort word = (ushort)((buffer[i] << 8) | (i + 1 < buffer.Length ? buffer[i + 1] : 0));
            checksum += word;

            // Handle carry bit if necessary
            if (checksum > 0xFFFF)
            {
                checksum = (checksum & 0xFFFF) + 1;
            }
        }

        checksum = ~checksum; 

        return (ushort)(checksum & 0xFFFF);  // Return lower 16-bits
    }

}
