using System.CommandLine;
using System.CommandLine.NamingConventionBinder;

namespace ipk_l4_scan.CmdLineArgParser
{
    public class CmdLineArgParser
    {
        public string Interface { get; set; } = string.Empty;
        public String UdpPorts { get; set; } = string.Empty;
        public String TcpPorts { get; set; } = string.Empty;
        public int Timeout { get; set; } = 5000;
        public string Target { get; set; } = string.Empty;

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
                    "UDP port ranges" 
                ),
                new Option<string>(
                    ["-t", "--pt"],
                    "TCP port ranges" 
                ),
                new Option<int>(
                    ["-w", "--wait"],
                    () => 5000,
                    "Timeout in milliseconds for single port scan" 
                ),
                new Argument<string>(
                    "target",
                    "Domain name or ip-address"
                )
            };

            rootCommand.Handler = CommandHandler.Create<string, string, string, int, string>((i, u, t, w, target) =>
            {
                Interface = i;
                UdpPorts = u;
                TcpPorts = t;
                Timeout = w;
                Target = target;
            });

            rootCommand.Invoke(args);
        }

        public void PrintParsedArgs()
        {
            Console.WriteLine($"Interface: {Interface}");
            Console.WriteLine($"UDP Port/s: {string.Join(", ", UdpPorts)}");
            Console.WriteLine($"TCP Port/s: {string.Join(", ", TcpPorts)}");
            Console.WriteLine($"Timeout: {Timeout} milliseconds");
            Console.WriteLine($"Target: {Target}");
            Console.WriteLine();
        }
    }

    public static class PortParser
    {
        public static int[] ToPortArray(this string ports)
        {
            if (ports.Contains(','))
                return ports.SplitStringBy(',');

            if (ports.Contains('-'))
                return ports.SplitStringBy('-');

            return int.TryParse(ports, out var result) ? [result] : [];
        }

        private static int[] SplitStringBy(this string ports, char separator)
        {
            return ports.Split(separator)
                .Select(port => int.TryParse(port, out int result) ? result : (int?)null)
                .Where(port => port.HasValue)
                .Select(port => port.Value)
                .ToArray();
        }
    }
}
