using System.Net;

namespace ipk_l4_scan.headers;

public class IpV4
{
    public byte Version { get; set; } = 4;
    public byte HeaderLength { get; set; } = 5;
    public byte TypeOfService { get; set; } = 0;
    public ushort TotalLength { get; set; } = 40;
    public ushort Identification { get; set; } = 0xabcd;
    public byte Flags { get; set; } = 0;
    public ushort FragmentOffset { get; set; } = 0;
    public byte TimeToLive { get; set; } = 64;
    public byte Protocol { get; set; } = 6;
    public ushort HeaderChecksum { get; set; } = 0;
    public uint SourceAddress { get; set; }
    public uint DestinationAddress { get; set; }
    
    public IpV4(string sourceIP, string destIP)
    {
        SourceAddress = IpStringToUint(sourceIP);
        DestinationAddress = IpStringToUint(destIP);
    }
    
    private uint IpStringToUint(string ip)
    {
        var ipAddr = IPAddress.Parse(ip);
        byte[] bytes = ipAddr.GetAddressBytes();
        return BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
    }
    
    private string UintToIpString(uint address)
    {
        byte[] bytes = BitConverter.GetBytes(address).Reverse().ToArray();
        return new IPAddress(bytes).ToString();
    }
    
    public byte[] ToByteArray()
    {
        byte[] header = new byte[20];
        header[0] = (byte)((Version << 4) | HeaderLength);  // Version + IHL
        header[1] = TypeOfService;
        header[2] = (byte)(TotalLength >> 8); // High byte
        header[3] = (byte)(TotalLength & 0xFF); // Low byte
        header[4] = (byte)(Identification >> 8); // same 
        header[5] = (byte)(Identification & 0xFF);
        header[6] = (byte)((Flags << 5) | (FragmentOffset >> 8));
        header[7] = (byte)(FragmentOffset & 0xFF);
        header[8] = TimeToLive;
        header[9] = Protocol;
        header[10] = 0;
        header[11] = 0;
        
        // Convert source and destination addresses to bytes and ensure they are in network byte order (big-endian)
        byte[] sourceBytes = BitConverter.GetBytes(SourceAddress).Reverse().ToArray();
        byte[] destinationBytes = BitConverter.GetBytes(DestinationAddress).Reverse().ToArray();

        sourceBytes.CopyTo(header, 12);
        destinationBytes.CopyTo(header, 16);
        
        // Calculate checksum after the header is fully constructed
        HeaderChecksum = CalculateCheckSum(header);
        header[10] = (byte)(HeaderChecksum >> 8);
        header[11] = (byte)(HeaderChecksum & 0xFF);

        // Verify checksum
        if (CalculateCheckSum(header) == 0)
        {
            Console.WriteLine("IpV4 Checksum correct");
        }
        else
        {
            Console.WriteLine("IpV4 Checksum incorrect");
        }
        
        // Print out the IP addresses
        Console.WriteLine($"Source IP: {UintToIpString(SourceAddress)}");
        Console.WriteLine($"Destination IP: {UintToIpString(DestinationAddress)}");

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

        Console.WriteLine($"IP Checksum calculated: {checksum}");
        Console.WriteLine($"Checksum: 0x{checksum:X4}");
        Console.WriteLine("");
        return (ushort)(checksum & 0xFFFF);
    }
}
