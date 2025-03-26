using System.Collections.Concurrent;
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
    private readonly IPAddress _dstIp;
    
    private  CancellationTokenSource _tokenSource;

    public PortScanner(CmdLineArgParser.CmdLineArgParser parser, IPAddress dstIp)
    {
        _scannerSocket = SocketInitializer.InitSocket(parser.Interface, dstIp);

        _srcIp = dstIp.AddressFamily == AddressFamily.InterNetwork
            ? SocketInitializer.GetInterfaceIpv4Address(parser.Interface)
            : SocketInitializer.GetInterfaceIpv6Address(parser.Interface);
        _dstIp = dstIp;
        _tokenSource = new CancellationTokenSource();
    }

    public async Task InitScannerAsync(CmdLineArgParser.CmdLineArgParser parser)
    {
        var token = _tokenSource.Token;
        try
        {
            var srcPort = GetScannerSourcePort();
            // Initialize packet capturing
            var packetCapture = new PacketCapture(_scannerSocket, srcPort, parser.ports, _dstIp);
            _ = Task.Run(() => packetCapture.CapturePacketAsync(), token);

            await Task.Delay(1000, token); // Wait for packet capture to start
            
            await ScanPortsAsync(parser, srcPort);

            await Task.Delay(parser.Timeout, token); // Wait for responses
            
            // Print open UDP ports, we did not get response from them after timeout ran out
            PrintOpenUdpPorts(parser, packetCapture, _dstIp);
            
            // If there are any ports left, rescan them
            if (!parser.ports.IsEmpty)
            {
                await RescanPortsAsync(parser, srcPort, token, packetCapture);
            }
        }
        finally
        {
            _scannerSocket.Close();
            _tokenSource.Dispose();
        }
    }

    private async Task RescanPortsAsync(CmdLineArgParser.CmdLineArgParser parser, int srcPort, CancellationToken token,
        PacketCapture packetCapture)
    {
        foreach (var portEntry in parser.ports)
        {
            var port = portEntry.Key.Port;
            var protocolNum = portEntry.Key.Protocol;
                
            var protocol = protocolNum == 6 ? PacketBuilder.Protocol.Tcp : PacketBuilder.Protocol.Udp;
            await SendPacketAsync(protocol, srcPort, port);
        }
        
        await Task.Delay(parser.Timeout, token);
        
        // Print filtered ports, so ports that we did not get response from after rescan
        foreach (var portEntry in parser.ports)
        {
            var port = portEntry.Key.Port;
            var protocolNum = portEntry.Key.Protocol;
            packetCapture.PrintInfo(_dstIp, (ushort)port, (byte)protocolNum, 0);
        }
    }

    private async Task ScanPortsAsync(CmdLineArgParser.CmdLineArgParser parser, int srcPort)
    {
        // each port scan has its own task 
        var tasks = new List<Task>();

        foreach (var portEntry in parser.ports)
        {
            var port = portEntry.Key.Port;
            var protocolNum = portEntry.Key.Protocol == 6 ? PacketBuilder.Protocol.Tcp : PacketBuilder.Protocol.Udp;
            tasks.Add(SendPacketAsync(protocolNum, srcPort, port));
        }

        await Task.WhenAll(tasks);
    }

    private async Task SendPacketAsync(PacketBuilder.Protocol protocol, int srcPort, int port)
    {
        // Create packet and send it
        var packet = new PacketBuilder(_srcIp, _dstIp, srcPort).CreatePacket((ushort)port, protocol);
        var remoteEndPoint = RemoteEndPoint.InitRemoteEndPoint(_dstIp);
        
        try
        {
            await _scannerSocket.SendToAsync(packet, SocketFlags.None, remoteEndPoint);
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error sending packet to port {port}: {e.Message}");
        }
    }
    
    private void PrintOpenUdpPorts(CmdLineArgParser.CmdLineArgParser parser, PacketCapture packetCapture, IPAddress dstIp)
    {
        foreach (var portEntry in parser.ports.Where(p => p.Key.Protocol == 17))
        {
            int port = portEntry.Key.Port; // Extract the port number
            int protocolNum = portEntry.Key.Protocol; // Extract the protocol number
            parser.ports.TryRemove((port, 17), out _);
            packetCapture.PrintInfo(_dstIp, (ushort)port, (byte)protocolNum, 0x12);
        }
    }

    private static int GetScannerSourcePort()
    {
        if (_scannerSocket.LocalEndPoint == null)
            throw new InvalidOperationException("Socket not bound");
            
        return ((IPEndPoint)_scannerSocket.LocalEndPoint).Port;
    }
}