using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ipk_l4_scan.socket;

public static class ScannerSocket
{ 
    private static IPAddress? GetAddress(string interfaceName)
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name != interfaceName) continue;
                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    var ipAddress = ip.Address;
                    return ipAddress;
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            Environment.Exit(1);
            throw;
        }
        
        return null;
    }

    public static Socket InitSocket(string interfaceName)
    {
        IPAddress address = GetAddress(interfaceName);
        IPEndPoint localEp = new IPEndPoint(address, 12345);
        var scanner = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
        scanner.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        scanner.Bind(localEp);
        return scanner;
    }
    
    
}