using ipk_l4_scan.portScanner;

namespace ipk_l4_scan
{
  class Program
  {
    static int Main(string[] args)
    {
      var cmdLineArgParser = new CmdLineArgParser.CmdLineArgParser();
      cmdLineArgParser.ParseCmdLineArgs(args);
      cmdLineArgParser.PrintParsedArgs();
      
      var scanner = new PortScanner(cmdLineArgParser);
      scanner.StartScanner(cmdLineArgParser);

      return 0;
    }
  }
}
