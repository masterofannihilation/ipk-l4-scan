using System.Net;
using System.Security.AccessControl;

namespace ipk_l4_scan.headers;

public class UdpHeader
{
    private readonly ushort _srcPort;
    private readonly ushort _dstPort;
    private readonly byte _length;
    private ushort _checksum;
    private readonly uint _srcIp;
    private readonly uint _dstIp;

    public UdpHeader(ushort srcPort, ushort dstPort, IPAddress srcIp, IPAddress dstIp)
    {
        _srcPort = srcPort;
        _dstPort = dstPort;
        _srcIp = IpAddressToUint(srcIp.ToString());
        _dstIp = IpAddressToUint(dstIp.ToString());
        _length = 8;
    }

    private static uint IpAddressToUint(string ip)
    {
        var ipAddr = IPAddress.Parse(ip);
        byte[] bytes = ipAddr.GetAddressBytes();
        return BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
    }

    public byte[] CreateHeader()
    {
        byte[] header = new byte[8];
        
        header[0] = (byte)(_srcPort >> 8);
        header[1] = (byte)(_srcPort & 0xFF);
        header[2] = (byte)(_dstPort >> 8);
        header[3] = (byte)(_dstPort & 0xFF);
        header[4] = (byte)(_length >> 8);
        header[5] = (byte)(_length & 0xFF);

        _checksum = CalculateChecksum(header);
        header[6] = (byte)(_checksum >> 8);
        header[7] = (byte)(_checksum & 0xFF);
        
        return header;
    }

    private ushort CalculateChecksum(byte[] udpHeader)
    {
       byte[] pseudoHeader = PreparePseudoHeader(udpHeader);
       
       uint sum = 0;

       // Sum 16-bit words
       for (int i = 0; i < pseudoHeader.Length; i += 2)
       {
           ushort word = (ushort)((pseudoHeader[i] << 8) + (i + 1 < pseudoHeader.Length ? pseudoHeader[i + 1] : 0));
           sum += word;
       }

       // Fold 32-bit sum to 16-bit
       while ((sum >> 16) > 0)
           sum = (sum & 0xFFFF) + (sum >> 16);

       // One's complement
       return (ushort)~sum;
    }

    private byte[] PreparePseudoHeader(byte[] udpHeader)
    {
        byte[] pseudoHeader = new byte[12 + _length];
        BitConverter.GetBytes(_srcIp).Reverse().ToArray().CopyTo(pseudoHeader, 0);
        BitConverter.GetBytes(_dstIp).Reverse().ToArray().CopyTo(pseudoHeader, 4);
        pseudoHeader[8] = 0;
        pseudoHeader[9] = 17;
        pseudoHeader[10] = (byte)(_length >> 8);
        pseudoHeader[11] = (byte)(_length & 0xFF);

        Array.Copy(udpHeader, 0, pseudoHeader, 12, 8);
        
        return pseudoHeader;
    }
}