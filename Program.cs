using System.Collections.Concurrent;
using System.Net;
using ipk_l4_scan.portScanner;
using ipk_l4_scan.scannerSocket;

namespace ipk_l4_scan
{
  class Program
  {
    static async Task Main(string[] args)
    {
      var cmdLineArgParser = new CmdLineArgParser.CmdLineArgParser();
      cmdLineArgParser.ParseCmdLineArgs(args);

      // save ports to scan
      var ports = new ConcurrentDictionary<(int Port, int Protocol), byte>(cmdLineArgParser.ports);
      // get all available hosts addresses, get rid of ipv6 addresses if interface does not support it
      List<IPAddress> hosts = SocketInitializer.GetHostAddresses(cmdLineArgParser.Target, cmdLineArgParser.Interface);
      
      foreach (var host in hosts)
      {
        cmdLineArgParser.ports = new ConcurrentDictionary<(int Port, int Protocol), byte>(ports);
        var scanner = new PortScanner(cmdLineArgParser, host);
        await scanner.InitScannerAsync(cmdLineArgParser);
      }
    }
  }
}
