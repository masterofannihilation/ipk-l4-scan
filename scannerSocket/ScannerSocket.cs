using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ipk_l4_scan.socket;

public class ScannerSocket
{
    public static Socket InitSocket(string interfaceName)
    {
        IPAddress ipAddress = GetInterfaceIpAddress(interfaceName);
        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            return InitIpV4Socket(ipAddress);
        }
        return InitIpV6Socket(ipAddress);
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
            var scanner = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Tcp);
            scanner.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, true);
            scanner.Bind(localEndPoint);
            return scanner;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing IPv6 socket: {ex.Message}");
            throw;
        }
    }

    public static IPAddress GetInterfaceIpAddress(string interfaceName)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.Name == interfaceName)
                .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
                .Select(ip => ip.Address)
                .FirstOrDefault() ?? throw new Exception($"Cannot find an IP address for {interfaceName}.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}