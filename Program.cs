using ipk_l4_scan.portScanner;

//TODO reformat packet constructor

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
      scanner.InitScanner(cmdLineArgParser);

      return 0;
    }
  }
}
