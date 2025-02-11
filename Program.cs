using System;
using ipk_l4_scan.argParser;

namespace ipk_l4_scan
{
  class Program
  {
    static int Main(string[] args)
    {
      var parser = new ArgParser();
      int result = parser.GetArgs(args);

      Console.WriteLine($"Interface: {parser.Interface}");
      Console.WriteLine($"UDP Port Ranges: {parser.UdpPorts}");
      Console.WriteLine($"TCP Port Ranges: {parser.TcpPorts}");
      Console.WriteLine($"Timeout: {parser.Timeout} milliseconds");
      Console.WriteLine($"Target: {parser.Target}");

      return result;
    }
  }
}
