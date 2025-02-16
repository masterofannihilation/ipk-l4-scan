using System.Net;
using System.Net.Sockets;
using ipk_l4_scan.headers;

namespace ipk_l4_scan.packet;

public class Packet
{
    public static byte[] CraftPacket(string srcIp, string dstIp, ushort srcPort, ushort dstPort)
    {
        IpV4 ipV4 = new IpV4(srcIp,dstIp);
        byte[] ipV4Header = ipV4.ToByteArray();
        
        Tcp tcp = new Tcp(srcPort,dstPort, srcIp, dstIp);
        byte[] tcpHeader = tcp.ToByteArray();
        
        byte[] packet = new byte[ipV4Header.Length + tcpHeader.Length];
        Array.Copy(ipV4Header, 0, packet, 0, ipV4Header.Length);
        Array.Copy(tcpHeader, 0, packet, ipV4Header.Length, tcpHeader.Length);
        
        return packet;
    }

    public static void SendPacket(Socket socket, byte[] packet, IPEndPoint remoteEp)
    {
        try
        {
            socket.SendTo(packet, remoteEp);
            Console.WriteLine("Packet sent");
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            throw;
        }
    }
}