using System.CommandLine.Parsing;
using System.Net;
using System.Net.Sockets;
using ipk_l4_scan.packet;
using ipk_l4_scan.remoteEndPoint;
using ipk_l4_scan.scannerSocket;

namespace ipk_l4_scan.portScanner;

public class PortScanner
{
    private static Socket _scannerSocket = null!;
    private static readonly HashSet<ushort> OpenUdpPorts = new();
    private readonly IPAddress _srcIp;

    public PortScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        _scannerSocket = ScannerSocket.InitSocket(parser.Interface, parser.Target);

        IPAddress dstAddress = RemoteEndPoint.ResolveIpAddress(parser.Target);
        
        if (dstAddress.AddressFamily == AddressFamily.InterNetwork)
            _srcIp = ScannerSocket.GetInterfaceIpv4Address(parser.Interface);
        else
            _srcIp = ScannerSocket.GetInterfaceIpv6Address(parser.Interface);
    }

    public void InitScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        var captureResponse = Task.Run(() => PacketCapturer.CapturePacket(parser.Interface, _scannerSocket));
        Thread.Sleep(1000);

        if (!string.IsNullOrEmpty(parser.TcpPorts))
            ScanPorts(parser, PacketCrafter.Protocol.Tcp);

        if (!string.IsNullOrEmpty(parser.UdpPorts))
            ScanPorts(parser, PacketCrafter.Protocol.Udp);

        captureResponse.Wait();
        _scannerSocket.Close();
    }
    
    private void ScanPorts(CmdLineArgParser.CmdLineArgParser parser, PacketCrafter.Protocol protocol)
    {
        var tasks = new List<Task>();
        var ports = protocol == PacketCrafter.Protocol.Tcp ? parser.TcpPorts : parser.UdpPorts;

        foreach (var port in GetPorts(ports))
        {
            var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);
            var srcPort = GetSourcePort();
            
            ScanPort(parser, protocol, tasks, dstIp, srcPort, port);
        }

        Task.WaitAll(tasks.ToArray());
    }

    private void ScanPort(CmdLineArgParser.CmdLineArgParser parser, PacketCrafter.Protocol protocol, List<Task> tasks, IPAddress dstIp, int srcPort, int port)
    {
        tasks.Add(Task.Run(() =>
        {
            var packet = new PacketCrafter(_srcIp, dstIp, srcPort).CreatePacket((ushort)port, protocol);
            IPEndPoint remoteEndPoint = RemoteEndPoint.InitRemoteEndPoint(parser.Target, port);
            SendPacket(packet, remoteEndPoint);

            return Task.CompletedTask;
        }));
    }

    private static void SendPacket(byte[] packet, IPEndPoint remoteEndPoint)
    {
        try
        {
            _scannerSocket.SendTo(packet, remoteEndPoint);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
            throw;
        }
    }

    private static int GetSourcePort()
    {
        if (_scannerSocket.LocalEndPoint != null)
        {
            return ((IPEndPoint)_scannerSocket.LocalEndPoint).Port;
        }
        throw new Exception("LocalEndPoint is null. Socket may not be bound or connected.");
    }

    private async void WaitForIcmpMessage(ushort port)
    {
        await Task.Delay(1000); // Wait for 1 second to receive ICMP response
        if (!OpenUdpPorts.Contains(port))
        {
            Console.Write($"{port}\\udp");
            Console.SetCursorPosition(15, Console.CursorTop);
            Console.Write("OPEN\n");
            OpenUdpPorts.Add(port);
        }
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