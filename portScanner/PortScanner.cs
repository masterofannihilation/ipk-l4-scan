using System.Net;
using System.Net.Sockets;
using ipk_l4_scan.packet;
using ipk_l4_scan.remoteEndPoint;
using ipk_l4_scan.scannerSocket;

namespace ipk_l4_scan.portScanner;

public class PortScanner
{
    private static Socket _scannerSocket = null!;
    private readonly IPAddress _srcIp;
    
    private CancellationTokenSource _tokenSource;

    public PortScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        _scannerSocket = SocketInitializer.InitSocket(parser.Interface, parser.Target);

        IPAddress dstAddress = RemoteEndPoint.ResolveIpAddress(parser.Target);
        _srcIp = dstAddress.AddressFamily == AddressFamily.InterNetwork
            ? SocketInitializer.GetInterfaceIpv4Address(parser.Interface)
            : SocketInitializer.GetInterfaceIpv6Address(parser.Interface);
        
        _tokenSource = new CancellationTokenSource();
    }

    public async Task InitScannerAsync(CmdLineArgParser.CmdLineArgParser parser)
    {
        var token = _tokenSource.Token;
        try
        {
            var srcPort = GetScannerSourcePort();
            var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);
            var packetCapture = new PacketCapture(_scannerSocket, srcPort, parser.ports);

            _ = Task.Run(() => packetCapture.CapturePacketAsync(token), token);
            Console.WriteLine("Packet capture started...");

            await Task.Delay(1000, token); // Wait for packet capture to start

            Console.WriteLine("Scanning ports...");
            await ScanPortsAsync(parser, srcPort);

            Console.WriteLine("Waiting for responses...");
            await Task.Delay(parser.Timeout, token); // Wait for responses
            
            // Print open UDP ports
            PrintOpenUdpPorts(parser, packetCapture, dstIp);
            
            if (parser.ports.Any())
                Console.WriteLine("Sending packets again...");
                await RescanPortsAsync(parser, dstIp, srcPort, token, packetCapture);
        }
        finally
        {
            Console.WriteLine("Closing scanner socket...");
            _scannerSocket.Close();
            _tokenSource.Dispose();
        }
    }

    private async Task RescanPortsAsync(CmdLineArgParser.CmdLineArgParser parser, IPAddress dstIp, int srcPort, CancellationToken token,
        PacketCapture packetCapture)
    {
        foreach (var portEntry in parser.ports)
        {
            int port = portEntry.Key.Port; // Extract the port number
            int protocolNum = portEntry.Key.Protocol; // Extract the protocol number
                
            // Example: Send a packet (replace with your logic)
            var protocol = protocolNum == 6 ? PacketBuilder.Protocol.Tcp : PacketBuilder.Protocol.Udp;
            await SendPacketAsync(parser, protocol, dstIp, srcPort, port);
        }
            
        Console.WriteLine("Waiting for responses...");
        await Task.Delay(parser.Timeout, token); // Wait for responses
        foreach (var portEntry in parser.ports)
        {
            int port = portEntry.Key.Port; // Extract the port number
            int protocolNum = portEntry.Key.Protocol; // Extract the protocol number
            packetCapture.PrintInfo(dstIp, (ushort)port, (byte)protocolNum, 0);
        }
    }

    private async Task ScanPortsAsync(CmdLineArgParser.CmdLineArgParser parser, int srcPort)
    {
        var tasks = new List<Task>();
        var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);

        foreach (var portEntry in parser.ports)
        {
            var port = portEntry.Key.Port;
            var protocolNum = portEntry.Key.Protocol == 6 ? PacketBuilder.Protocol.Tcp : PacketBuilder.Protocol.Udp;
            tasks.Add(SendPacketAsync(parser, protocolNum, dstIp, srcPort, port));
        }

        await Task.WhenAll(tasks);
    }

    private async Task SendPacketAsync(CmdLineArgParser.CmdLineArgParser parser, PacketBuilder.Protocol protocol, 
        IPAddress dstIp, int srcPort, int port)
    {
        var packet = new PacketBuilder(_srcIp, dstIp, srcPort).CreatePacket((ushort)port, protocol);
        var remoteEndPoint = RemoteEndPoint.InitRemoteEndPoint(parser.Target, port);
        
        try
        {
            await _scannerSocket.SendToAsync(packet, SocketFlags.None, remoteEndPoint);
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error sending packet to port {port}: {e.Message}");
        }
    }
    
    private static void PrintOpenUdpPorts(CmdLineArgParser.CmdLineArgParser parser, PacketCapture packetCapture, IPAddress dstIp)
    {
        foreach (var portEntry in parser.ports.Where(p => p.Key.Protocol == 17)) // 17 is the protocol number for UDP
        {
            int port = portEntry.Key.Port; // Extract the port number
            int protocolNum = portEntry.Key.Protocol; // Extract the protocol number (will always be 17 here)
            parser.ports.TryRemove((port, 17), out _);
            packetCapture.PrintInfo(dstIp, (ushort)port, (byte)protocolNum, 0x12);
        }
    }

    private static int GetScannerSourcePort()
    {
        if (_scannerSocket.LocalEndPoint == null)
            throw new InvalidOperationException("Socket not bound");
            
        return ((IPEndPoint)_scannerSocket.LocalEndPoint).Port;
    }
}