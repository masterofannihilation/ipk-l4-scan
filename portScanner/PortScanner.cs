using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using ipk_l4_scan.packet;
using ipk_l4_scan.remoteEndPoint;
using ipk_l4_scan.socket;
using SharpPcap;

namespace ipk_l4_scan.portScanner;

public class PortScanner
{
    private Socket scannerSocket;
        
    public PortScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        scannerSocket = ScannerSocket.InitSocket(parser.Interface);
    }
    public void StartScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        var captureResponse = Task.Run(() => Packet.CapturePacket(parser.Interface));
        Thread.Sleep(1000);
        
        ScanPorts(parser);
            
        captureResponse.Wait();
        scannerSocket.Close();
    }

    private void ScanPorts(CmdLineArgParser.CmdLineArgParser parser)
    {
        var tasks = new List<Task>();

        foreach (var port in GetPorts(parser.TcpPorts))
        {
            tasks.Add(Task.Run(() =>
            {
                var packet = new Packet(ScannerSocket.GetInterfaceIpAddress(parser.Interface),
                    RemoteEndPoint.ResolveIpAddress(parser.Target),
                    ((IPEndPoint)scannerSocket.LocalEndPoint).Port);

                IPEndPoint remoteEndPoint = RemoteEndPoint.InitRemoteEndPoint(parser.Target, port);

                Packet.SendPacket(scannerSocket, packet.CraftPacket((ushort)port), remoteEndPoint);
            }));
        }

        Task.WaitAll(tasks.ToArray());
    }
    
    private IEnumerable<int> GetPorts(string portInput)
    {
        if (portInput.Contains(','))
        {
            return GetIndividualPorts(portInput);
        }
        if (portInput.Contains('-'))
        {
            return GetPortRange(portInput);
        }
        return new List<int> { GetSinglePort(portInput) };
    }

    private IEnumerable<int> GetIndividualPorts(string portInput)
    {
        var ports = portInput.Split(',');
        foreach (var port in ports)
        {
            yield return int.Parse(port);
        }
    }

    private IEnumerable<int> GetPortRange(string portInput)
    {
        var range = portInput.Split('-');
        int startPort = int.Parse(range[0]);
        int endPort = int.Parse(range[1]);

        for (int port = startPort; port <= endPort; port++)
        {
            yield return port;
        }
    }

    private int GetSinglePort(string portInput)
    {
        return int.Parse(portInput);
    }
}