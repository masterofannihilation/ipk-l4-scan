using System.CommandLine;
using System.CommandLine.NamingConventionBinder;

namespace ipk_l4_scan.CmdLineArgParser
{
    public class CmdLineArgParser
    {
        public string Interface = string.Empty;
        public String UdpPorts = string.Empty;
        public String TcpPorts = string.Empty;
        public int Timeout = 5000;
        public string Target = string.Empty;

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
}
