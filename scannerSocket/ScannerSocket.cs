using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ipk_l4_scan.scannerSocket;

public abstract class ScannerSocket
{
    public static Socket InitSocket(string interfaceName, string dstIp)
    {
        if (!IPAddress.TryParse(dstIp, out var dstAddress))
        {
            dstAddress = Dns.GetHostAddresses(dstIp).FirstOrDefault() ?? throw new InvalidOperationException();
        }

        IPAddress ipAddress;

        if (dstAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            ipAddress = GetInterfaceIpv4Address(interfaceName);
            return InitIpV4Socket(ipAddress);
        }
        if (dstAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            ipAddress = GetInterfaceIpv6Address(interfaceName);
            return InitIpV6Socket(ipAddress);
        }

        throw new NotSupportedException("Unsupported IP address family.");
    }
    private static Socket InitIpV4Socket(IPAddress address)
    {
        try
        {
            IPEndPoint localEndPoint = new IPEndPoint(address, 0);
            var scanner = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
            scanner.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            scanner.Bind(localEndPoint);
            return scanner;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing IpV4 socket: {ex.Message}");
            throw;
        }
    }
    
    private static Socket InitIpV6Socket(IPAddress address)
    {
        try
        {
            IPEndPoint localEndPoint = new IPEndPoint(address, 0);
            var scanner = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Raw);
            scanner.Bind(localEndPoint);
            return scanner;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing IPv6 socket: {ex.Message}");
            throw;
        }
    }

    public static IPAddress GetInterfaceIpv4Address(string interfaceName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                       .Where(ni => ni.Name == interfaceName)
                       .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                       .Select(ip => ip.Address)
                       .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork) 
                   ?? throw new Exception($"Cannot find an IPv4 address for {interfaceName}.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
    
    public static IPAddress GetInterfaceIpv6Address(string interfaceName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                       .Where(ni => ni.Name == interfaceName)
                       .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                       .Select(ip => ip.Address)
                       .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetworkV6) 
                   ?? throw new Exception($"Cannot find an IPv6 address for {interfaceName}.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}