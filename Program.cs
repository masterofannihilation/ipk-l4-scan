using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using ipk_l4_scan.portScanner;
using ipk_l4_scan.scannerSocket;

namespace ipk_l4_scan
{
  class Program
  {
    static async Task Main(string[] args)
    {
      var cmdLineArgParser = new CmdLineArgParser.CmdLineArgParser();
      cmdLineArgParser.PrintInterfacesIfNecessary(args);
      cmdLineArgParser.ParseCmdLineArgs(args);

      // save ports to scan
      var ports = new ConcurrentDictionary<(int Port, int Protocol), byte>(cmdLineArgParser.ports);
      // get all available hosts addresses, get rid of ipv6 addresses if interface does not support it
      List<IPAddress> hosts = SocketInitializer.GetHostAddresses(cmdLineArgParser.Target, cmdLineArgParser.Interface);
      // if localhost is specified, hardcode it to 127.0.0.1
      if (cmdLineArgParser.Target == "localhost")
      {
        hosts = [IPAddress.Parse("127.0.0.1")];
        cmdLineArgParser.Target = "127.0.0.1";
      }
      
      foreach (var host in hosts)
      {
        cmdLineArgParser.ports = new ConcurrentDictionary<(int Port, int Protocol), byte>(ports);
        var scanner = new PortScanner(cmdLineArgParser, host);
        await scanner.InitScannerAsync(cmdLineArgParser);
      }
    }
  }
}
