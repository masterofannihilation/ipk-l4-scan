using System.CommandLine;
using System.CommandLine.NamingConventionBinder;

namespace ipk_l4_scan.CmdLineArgParser
{
    public class CmdLineArgParser
    {
        public string Interface = string.Empty;
        public IEnumerable<int> UdpPorts = [];
        public IEnumerable<int> TcpPorts = [];
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
                UdpPorts = GetPorts(u);
                TcpPorts = GetPorts(t);
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
        
        public IEnumerable<int> GetPorts(string portInput)
        {   
            if (portInput == null)
            {
                return new List<int>();
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
}
