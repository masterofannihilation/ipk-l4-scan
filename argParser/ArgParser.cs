using System;
using System.Linq;
using System.Net.NetworkInformation;

namespace ipk_l4_scan.argParser
{
  public class ArgParser
  {
    public string InterfaceName { get; set; } = string.Empty;
    public string UdpPorts { get; set; } = string.Empty;
    public string TcpPorts { get; set; } = string.Empty;
    public int Timeout { get; set; } = 5000;
    public string Target { get; set; } = string.Empty;

    public bool UdpRange { get; set; } = false;
    public bool TcpRange { get; set; } = false;
    string[] portsArray = Array.Empty<string>();

    public void GetArgs(string[] args)
    {
      for(int i = 0; i < args.Length - 1; i++)
      {
        var currArg = args[i];
        switch(currArg)
        {
          case "-i":
          case "--interface":
            InterfaceName = args[i + 1];
            i++; 
            break;
          
          case "-u":
          case "--pu":
            UdpPorts = args[i + 1];
            i++; 
            break;
          
          case "-t":
          case "--pt":
            TcpPorts = args[i + 1];
            i++; 
            break;

          case "-w":
          case "--wait":
            Timeout = int.Parse(args[i + 1]);
            i++;
            break;

          default:
            Target = args[i];
            break;
        }  
      }
    }
  }
}
