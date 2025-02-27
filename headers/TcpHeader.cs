using System.Net;

namespace ipk_l4_scan.headers;

public class TcpHeader
{
    public ushort SrcPort { get; set; }
    public ushort DestinationPort { get; set; }
    public uint SequenceNumber { get; set; } = 0;
    public uint AcknowledgmentNumber { get; set; } = 0;
    public byte DataOffset { get; set; } = 5;
    public byte Reserved { get; set; } = 0;
    public byte Flags { get; set; } = 0b00000010; // SYN flag set
    public ushort WindowSize { get; set; } = 1024;
    public ushort Checksum { get; set; } = 0;
    public ushort UrgentPointer { get; set; } = 0;
    
    private uint srcIp;
    private uint dstIp;

    public TcpHeader(ushort srcPort, ushort destPort, IPAddress srcIp, IPAddress dstIp)
    {
        SrcPort = srcPort;
        DestinationPort = destPort;
        this.srcIp = IpStringToUint(srcIp.ToString());
        this.dstIp = IpStringToUint(dstIp.ToString());
    }
    
    private uint IpStringToUint(string ip)
    {
        var ipAddr = IPAddress.Parse(ip);
        byte[] bytes = ipAddr.GetAddressBytes();
        return BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
    }

    public byte[] ToByteArray()
    {
        byte[] header = new byte[20];
        header[0] = (byte)(SrcPort >> 8);
        header[1] = (byte)(SrcPort & 0xFF);
        header[2] = (byte)(DestinationPort >> 8);
        header[3] = (byte)(DestinationPort & 0xFF);
        BitConverter.GetBytes(SequenceNumber).CopyTo(header, 4);
        BitConverter.GetBytes(AcknowledgmentNumber).CopyTo(header, 8);
        header[12] = (byte)((DataOffset << 4) | Reserved);
        header[13] = Flags;
        header[14] = (byte)(WindowSize >> 8);
        header[15] = (byte)(WindowSize & 0xFF);
        header[16] = 0; // Checksum before calc
        header[17] = 0;
        header[18] = (byte)(UrgentPointer >> 8);
        header[19] = (byte)(UrgentPointer & 0xFF);

        Checksum = CheckSum(header);
        header[16] = (byte)(Checksum >> 8);
        header[17] = (byte)(Checksum & 0xFF);

        return header;
    }

    private ushort CheckSum(byte[] header)
    {
        // Construct pseudo-header
        byte[] pseudoHeader = new byte[12 + header.Length];

        // Source & destination IPs (Big-endian)
        BitConverter.GetBytes(srcIp).Reverse().ToArray().CopyTo(pseudoHeader, 0);
        BitConverter.GetBytes(dstIp).Reverse().ToArray().CopyTo(pseudoHeader, 4);

        pseudoHeader[8] = 0;
        pseudoHeader[9] = 6;
        pseudoHeader[10] = (byte)(header.Length >> 8);  // High byte of TCP length
        pseudoHeader[11] = (byte)(header.Length & 0xFF);  // Low byte of TCP length

        // Copy TCP header
        Array.Copy(header, 0, pseudoHeader, 12, header.Length);

        return CalculateCheckSum(pseudoHeader);
    }

    private ushort CalculateCheckSum(byte[] buffer)
    {
        uint checksum = 0;

        // Process each 16-bit word (2 bytes at a time)
        for (int i = 0; i < buffer.Length; i += 2)
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
