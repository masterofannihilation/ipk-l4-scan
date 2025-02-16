using System;
using System.Net.NetworkInformation;
using ipk_l4_scan.argParser;
using ipk_l4_scan.scanner;

namespace ipk_l4_scan
{
  class Program
  {
    static int Main(string[] args)
    {
      var parser = new ArgParser();
      parser.GetArgs(args);
      Console.WriteLine($"Interface: {parser.InterfaceName}");
      Console.WriteLine($"UDP Port Ranges: {parser.UdpPorts}");
      Console.WriteLine($"TCP Port Ranges: {parser.TcpPorts}");
      Console.WriteLine($"Timeout: {parser.Timeout} milliseconds");
      Console.WriteLine($"Target: {parser.Target}");
      Console.WriteLine();
      
      var scanner = new Scanner();
      scanner.StartScanner(parser.InterfaceName);

      return 0;
    }
  }
}
