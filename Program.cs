using ipk_l4_scan.portScanner;

//TODO reformat packet constructor

namespace ipk_l4_scan
{
  class Program
  {
    static async Task Main(string[] args)
    {
      var cmdLineArgParser = new CmdLineArgParser.CmdLineArgParser();
      cmdLineArgParser.ParseCmdLineArgs(args);
      
      var scanner = new PortScanner(cmdLineArgParser);
      await scanner.InitScanner(cmdLineArgParser);
    }
  }
}
