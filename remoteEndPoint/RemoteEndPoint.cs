using System.Net;

namespace ipk_l4_scan.remoteEndPoint;

public class RemoteEndPoint
{
    public static IPEndPoint InitRemoteEndPoint(IPAddress target)
    {
        return new IPEndPoint(target, 0);
    }
}