using System.Net;

namespace ipk_l4_scan.headers;

public class IpV6Header
{
    private byte Version = 6;
    private byte TrafficClass = 0;
    private uint FlowLabel = 0 ;
    private ushort PayloadLength = 20;
    private byte NextHeader;
    private byte HopLimit = 64;
    private byte[] SourceAddress;
    private byte[] DestinationAddress;

    public IpV6Header(IPAddress srcIp, IPAddress dstIp, uint protocol)
    {
        SourceAddress = srcIp.GetAddressBytes();
        DestinationAddress = dstIp.GetAddressBytes();
        NextHeader = (byte)protocol;
    }

    public byte[] CreateHeader()
    {
        byte[] header = new byte[40];
        header[0] = (byte)((Version << 4) | (TrafficClass >> 4));
        header[1] = (byte)((uint)(TrafficClass << 4) | ((FlowLabel >> 16) & 0x0F));
        header[2] = (byte)((FlowLabel >> 8) & 0xFF);
        header[3] = (byte)(FlowLabel & 0xFF);
        header[4] = (byte)(PayloadLength >> 8);
        header[5] = (byte)(PayloadLength & 0xFF);
        header[6] = NextHeader;
        header[7] = HopLimit;
        Array.Copy(SourceAddress, 0, header, 8, 16);
        Array.Copy(DestinationAddress, 0, header, 24, 16);

        return header;
    }
}