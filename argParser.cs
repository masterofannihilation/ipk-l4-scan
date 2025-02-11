using System.CommandLine;
using System.CommandLine.NamingConventionBinder;

namespace ipk_l4_scan.argParser
{
  public class ArgParser
  {
     public string Interface { get; set; } = string.Empty;
    public string UdpPorts { get; set; } = string.Empty;
    public string TcpPorts { get; set; } = string.Empty;
    public int Timeout { get; set; } = 5000;
    public string Target { get; set; } = string.Empty;

    public int GetArgs(string[] args)
    {
      var rootCommand = new RootCommand
      {
        new Option<string>(
          new[] {"-i", "--interface"},
          "Network interface to scan"
        ),
        new Option<string>(
          new[] {"-u", "--pu"},
          "UDP port ranges" 
        ),
        new Option<string>(
          new[] {"-t", "--pt"},
          "TCP port ranges" 
        ),
        new Option<int>(
          new[] {"-w", "--wait"},
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

      return rootCommand.Invoke(args);
    }
  }
}
