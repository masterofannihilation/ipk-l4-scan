using System.Net;

namespace ipk_l4_scan.remoteEndPoint;

public class RemoteEndPoint
{
    public static IPEndPoint InitRemoteEndPoint(string target, int port)
    {
        var targetIpAddress = ResolveIpAddress(target);
        return new IPEndPoint(targetIpAddress, port);
    }

    public static IPAddress ResolveIpAddress(string target)
    {
        if (IsIpAddress(target))
            return IPAddress.Parse(target);
        
        return ResolveDomainIpAddress(target);
    }

    private static bool IsIpAddress(string target)
    {
        return IPAddress.TryParse(target, out _);
    }

    private static IPAddress ResolveDomainIpAddress(string domain)
    {
        try
        {
            return Dns.GetHostAddresses(domain)
                .FirstOrDefault() ?? throw new Exception($"Cannot find an IP address for {domain}.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }
}