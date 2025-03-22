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
    
    private readonly ConcurrentDictionary<int, bool> _tcpResponseTracker = new();
    private readonly ConcurrentDictionary<int, bool> _udpResponseTracker = new();
    private readonly ConcurrentDictionary<int, PacketBuilder.Protocol> _portProtocols = new();
    private readonly ConcurrentBag<int> _filteredPorts = new();
    private readonly ConcurrentBag<int> _sentUdpPorts = new();

    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource<bool> _initialScanComplete = new TaskCompletionSource<bool>();

    public PortScanner(CmdLineArgParser.CmdLineArgParser parser)
    {
        _scannerSocket = SocketInitializer.InitSocket(parser.Interface, parser.Target);

        IPAddress dstAddress = RemoteEndPoint.ResolveIpAddress(parser.Target);
        _srcIp = dstAddress.AddressFamily == AddressFamily.InterNetwork
            ? SocketInitializer.GetInterfaceIpv4Address(parser.Interface)
            : SocketInitializer.GetInterfaceIpv6Address(parser.Interface);
    }

    public async Task InitScanner(CmdLineArgParser.CmdLineArgParser parser)
{
    try
    {
        var srcPort = GetScannerSourcePort();
        var packetCapturer = new PacketCapture(_scannerSocket, srcPort, _tcpResponseTracker, _udpResponseTracker, _cts);

        var captureResponse = Task.Run(() => packetCapturer.CapturePacket(), _cts.Token);
        var retryTask = Task.Run(() => RetryUnresponsivedPorts(parser), _cts.Token);

        await Task.Delay(1000, _cts.Token); // Wait for packet capture to start

        if (parser.TcpPorts.Any())
        {
            Console.WriteLine("Scanning TCP ports...");
            await ScanPorts(parser, PacketBuilder.Protocol.Tcp, srcPort);
        }

        if (parser.UdpPorts.Any())
        {
            Console.WriteLine("Scanning UDP ports...");
            await ScanPorts(parser, PacketBuilder.Protocol.Udp, srcPort);
        }

        Console.WriteLine("Waiting for responses...");
        await Task.Delay(parser.Timeout, _cts.Token); // Wait for responses

        // Mark TCP ports as filtered if no response is received
        foreach (var port in parser.TcpPorts)
        {
            if (!_tcpResponseTracker.ContainsKey(port) || !_tcpResponseTracker[port])
            {
                var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);
                Console.WriteLine($"{dstIp} {port} tcp filtered");
            }
        }

        _cts.Cancel(); // Cancel tasks after timeout

        try
        {
            Console.WriteLine("Waiting for tasks to complete...");
            await Task.WhenAll(captureResponse, retryTask).WaitAsync(TimeSpan.FromSeconds(5)); // Add a timeout
        }
        catch (TimeoutException)
        {
            Console.WriteLine("Timeout while waiting for tasks to complete.");
        }

        Console.WriteLine("konec cisty");

        // Print open UDP ports
        foreach (var port in _sentUdpPorts)
        {
            if (!_udpResponseTracker.ContainsKey(port) || _udpResponseTracker[port])
                continue; // Skip closed or filtered ports

            var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);
            Console.WriteLine($"{dstIp} {port} udp open");
        }
    }
    finally
    {
        Console.WriteLine("Closing scanner socket...");
        _scannerSocket.Close();
        _cts.Dispose();
    }
}

    private async Task RetryUnresponsivedPorts(CmdLineArgParser.CmdLineArgParser parser)
    {
        try
        {
            // Wait for the initial scan to complete
            await _initialScanComplete.Task;

            while (!_cts.Token.IsCancellationRequested)
            {
                // Get ports that haven't responded and haven't been filtered yet
                var portsToRetry = _tcpResponseTracker
                    .Where(kvp => !kvp.Value && !_filteredPorts.Contains(kvp.Key))
                    .Select(kvp => kvp.Key)
                    .ToList();

                if (portsToRetry.Count == 0)
                {
                    break; // Exit the loop if no ports are left to retry
                }

                foreach (var port in portsToRetry)
                {
                    // Check if the port is TCP
                    if (!_portProtocols.TryGetValue(port, out var protocol) || protocol != PacketBuilder.Protocol.Tcp)
                        continue;

                    var srcPort = GetScannerSourcePort();
                    var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);

                    await SendPacket(parser, PacketBuilder.Protocol.Tcp, dstIp, srcPort, port);

                    // Mark the port as filtered if it still doesn't respond
                    if (!_tcpResponseTracker[port])
                    {
                        _filteredPorts.Add(port);
                        Console.WriteLine($"{dstIp} {port} tcp filtered");
                    }
                }

                await Task.Delay(parser.Timeout, _cts.Token); // Wait before retrying
            }
        }
        catch (Exception ex)
        {
            // Console.WriteLine($"Error in RetryUnresponsivedPorts: {ex.Message}");
        }
    }

    private async Task ScanPorts(CmdLineArgParser.CmdLineArgParser parser, PacketBuilder.Protocol protocol, int srcPort)
    {
        var tasks = new List<Task>();
        var ports = protocol == PacketBuilder.Protocol.Tcp ? parser.TcpPorts : parser.UdpPorts;

        foreach (var port in ports)
        {
            if (_filteredPorts.Contains(port)) // Skip filtered ports
                continue;

            var dstIp = RemoteEndPoint.ResolveIpAddress(parser.Target);

            if (protocol == PacketBuilder.Protocol.Tcp)
            {
                _tcpResponseTracker[port] = false; // Initialize TCP response tracker
            }
            else if (protocol == PacketBuilder.Protocol.Udp)
            {
                _udpResponseTracker[port] = false; // Initialize UDP response tracker
                _sentUdpPorts.Add(port); // Track sent UDP ports
            }

            _portProtocols[port] = protocol; // Track the protocol for this port
            tasks.Add(SendPacket(parser, protocol, dstIp, srcPort, port));
        }

        await Task.WhenAll(tasks);
    }

    private async Task SendPacket(CmdLineArgParser.CmdLineArgParser parser, PacketBuilder.Protocol protocol, 
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

    private static int GetScannerSourcePort()
    {
        if (_scannerSocket.LocalEndPoint == null)
            throw new InvalidOperationException("Socket not bound");
            
        return ((IPEndPoint)_scannerSocket.LocalEndPoint).Port;
    }
}