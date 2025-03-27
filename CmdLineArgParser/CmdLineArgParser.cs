using System.Collections.Concurrent;
using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.Net.NetworkInformation;

namespace ipk_l4_scan.CmdLineArgParser;

public class CmdLineArgParser
{
    public string Interface = string.Empty;
    // Dictionary of ports to scan, key is tuple of port number and protocol number, value is 0
    public ConcurrentDictionary<(int Port, int Protocol), byte> ports = new();
    public int Timeout = 5000;
    public string Target = string.Empty;

    public void PrintInterfacesIfNecessary(string[] args)
    {
        if (args.Length < 1 || (args.Length < 2 && (args[0] == "-i" || args[0] == "--interface")))
        {
            foreach (var host in NetworkInterface.GetAllNetworkInterfaces())
            {
                Console.WriteLine(host.Name);
            }
            Environment.Exit(0);
        }
    }

    public void ParseCmdLineArgs(string[] args)
    {
        var rootCommand = new RootCommand
        {
            new Option<string>(
                ["-i", "--interface"],
                "Network interface to use"
            ),
            new Option<string>(
                ["-u", "--pu"],
                "UDP port/s" 
            ),
            new Option<string>(
                ["-t", "--pt"],
                "TCP port/s" 
            ),
            new Option<int>(
                ["-w", "--wait"],
                () => 5000,
                "Timeout in milliseconds for single port scan" 
            ),
            new Argument<string>(
                "target",
                "Domain name or ip-address to scan"
            )
        };

        rootCommand.Handler = CommandHandler.Create<string, string, string, int, string>((i, u, t, w, target) =>
        {
            Interface = i;
            Timeout = w;
            Target = target;
            // parse ports from command line to desired format, so (PORT NUM, PROTOCOL NUM) 6 for TCP, 17 for UDP
            AddPortsToDictionary(u, t);
        });

        rootCommand.Invoke(args);
    }

    private void AddPortsToDictionary(string u, string t)
    {
        foreach (var port in GetPorts(u))
        {
            ports.TryAdd((port, 17), 0);
        }

        foreach (var port in GetPorts(t))
        {
            ports.TryAdd((port, 6), 0);
        }
    }

    private IEnumerable<int> GetPorts(string portInput)
    {   
        if (portInput == null)
        {
            return Enumerable.Empty<int>();
        }
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