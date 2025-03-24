using System.Net;

namespace ipk_l4_scan.headers;

public class IpV4Header
{
    private readonly byte _version = 4;
    private readonly byte _headerLength = 5;
    private readonly byte _typeOfService = 0;
    private readonly ushort _totalLength = 40;
    private readonly ushort _identification = 0xabcd;
    private readonly byte _flags = 0;
    private readonly ushort _fragmentOffset = 0;
    private readonly byte _timeToLive = 64;
    private readonly byte _protocol;
    private ushort _checksum;
    private readonly uint _sourceAddress;
    private readonly uint _destinationAddress;
    
    public IpV4Header(IPAddress srcIp, IPAddress dstIp, uint protocol)
    {
        _sourceAddress = IpStringToUint(srcIp.ToString());
        _destinationAddress = IpStringToUint(dstIp.ToString());
        _protocol = (byte)protocol;
    }
    
    private uint IpStringToUint(string ip)
    {
        var ipAddr = IPAddress.Parse(ip);
        byte[] bytes = ipAddr.GetAddressBytes();
        return BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
    }
    
    public byte[] CreateHeader()
    {
        byte[] header = new byte[20];
        
        header[0] = (byte)((_version << 4) | _headerLength);  // Version + IHL
        header[1] = _typeOfService;
        header[2] = (byte)(_totalLength >> 8); // High byte
        header[3] = (byte)(_totalLength & 0xFF); // Low byte
        header[4] = (byte)(_identification >> 8); // same 
        header[5] = (byte)(_identification & 0xFF);
        header[6] = (byte)((_flags << 5) | (_fragmentOffset >> 8));
        header[7] = (byte)(_fragmentOffset & 0xFF);
        header[8] = _timeToLive;
        header[9] = _protocol;
        header[10] = 0;
        header[11] = 0;
        
        byte[] sourceBytes = BitConverter.GetBytes(_sourceAddress).Reverse().ToArray();
        byte[] destinationBytes = BitConverter.GetBytes(_destinationAddress).Reverse().ToArray();
        sourceBytes.CopyTo(header, 12);
        destinationBytes.CopyTo(header, 16);

        // Calculate checksum after the header is fully constructed
        _checksum = CalculateCheckSum(header);
        header[10] = (byte)(_checksum >> 8);
        header[11] = (byte)(_checksum & 0xFF);

        return header;
    }

    private ushort CalculateCheckSum(byte[] header)
    {
        uint checksum = 0;

        for (int i = 0; i < 20; i += 2)
        {
            ushort word = (ushort)((header[i] << 8) | header[i + 1]);
            checksum += word;

            // Carry the overflow if necessary
            if (checksum > 0xFFFF)
                checksum = (checksum & 0xFFFF) + 1;
        }

        checksum = ~checksum;
        return (ushort)checksum;
    }
}
