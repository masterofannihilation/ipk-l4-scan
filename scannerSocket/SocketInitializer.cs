using System.CommandLine;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ipk_l4_scan.scannerSocket;

public abstract class SocketInitializer
{
    public static Socket InitSocket(string interfaceName, IPAddress dstIp)
    {
        IPAddress ipAddress;

        if (dstIp.AddressFamily == AddressFamily.InterNetwork)
        {
            ipAddress = GetInterfaceIpv4Address(interfaceName);
            return InitIpV4Socket(ipAddress);
        }
        if (dstIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            ipAddress = GetInterfaceIpv6Address(interfaceName);
            return InitIpV6Socket(ipAddress);
        }

        throw new NotSupportedException("Unsupported IP address family.");
    }
    
    public static List<IPAddress> GetHostAddresses(string hostName, string interfaceName)
    {
        var ipAddresses = NetworkInterface.GetAllNetworkInterfaces();
        bool ipv4 = false;
        bool ipv6 = false;

        foreach (var ip in ipAddresses)
        {
            if (ip.Name == interfaceName)
            {
                foreach (var ipProps in ip.GetIPProperties().UnicastAddresses)
                {
                    if (ipProps.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        ipv4 = true; // IPv4 is available
                    }
                    if (ipProps.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        // Check if the IPv6 address is global (not link-local or private)
                        if (ipProps.Address is { IsIPv6LinkLocal: false, IsIPv6SiteLocal: false })
                        {
                            ipv6 = true; // Global IPv6 is available
                        }
                    }
                }
            }
        }

        var hosts = new List<IPAddress>(Dns.GetHostAddresses(hostName) ?? throw new InvalidOperationException());

        // Filter hosts based on available IP versions
        foreach (var host in hosts.ToList())
        {
            if (host.AddressFamily == AddressFamily.InterNetwork && !ipv4)
            {
                hosts.Remove(host); // Remove IPv4 if not available
            }
            if (host.AddressFamily == AddressFamily.InterNetworkV6 && !ipv6)
            {
                hosts.Remove(host); // Remove IPv6 if not available
            }
        }

        return hosts;
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
    
    public static Socket InitIcmpV6Socket(string interfaceName)
    {
        var address = GetInterfaceIpv6Address(interfaceName);
        try
        {
            IPEndPoint localEndPoint = new IPEndPoint(address, 0);
            var scanner = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
            scanner.Bind(localEndPoint);
            return scanner;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing ICMPv6 socket: {ex.Message}");
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